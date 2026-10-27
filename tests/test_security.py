import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from configuration import addresses, compose, firewall, nginx_config, validate
from security import check_php, findings, read_lock
from nextcloud import Stack


class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.c = json.loads((ROOT / 'site.example.json').read_text())

    def test_supported_config(self):
        self.assertEqual(validate(self.c), self.c)

    def test_injections_and_unknown_options(self):
        for key, values in {
            'domain': ['cloud.test;include /tmp/a', '*.example.org', 'https://a.test', 'a.test\n'],
            'admin_user': ['admin;id', 'admin\n', 'a'],
            'wan_interface': ['lo', 'br-nc-back', 'eth0" accept #'],
            'certificate': ['/x;foo', '/etc/../tmp/cert', '/x\n'],
            'dns': [['127.0.0.1'], ['169.254.169.254'], ['::1'], []],
            'frontend_subnet': ['172.30.91.0/28', '172.30.90.1/28', '8.8.8.0/28', '172.30.90.0/24'],
            'maintenance_window_start': [-1, 24, True, '1'],
        }.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    c = copy.deepcopy(self.c)
                    c[key] = value
                    with self.assertRaises((ValueError, TypeError)):
                        validate(c)
        self.c['skip_security'] = True
        with self.assertRaises(ValueError):
            validate(self.c)

    def test_php_security_floor(self):
        for version in ['8.3.36', '8.4.27', '8.5.12', '8.5.13']:
            check_php(version)
        for version in ['8.2.35', '8.3.35', '8.4.26', '8.5.11', '8.5.12RC1', '9.0.0', 'unknown']:
            with self.subTest(version=version), self.assertRaises(ValueError):
                check_php(version)

    def test_no_cve_silently_ignored(self):
        for severity in ['HIGH', 'CRITICAL', 'UNKNOWN', 'FUTURE_SEVERITY']:
            for fixed in ['', '9.9']:
                report = {'SchemaVersion': 2, 'Results': [{'Vulnerabilities': [
                    {'VulnerabilityID': 'CVE-test', 'Severity': severity, 'FixedVersion': fixed}]}]}
                self.assertTrue(findings(report)[1])

    def test_secret_is_never_printed(self):
        report = {'SchemaVersion': 2, 'Results': [{'Secrets': [{'Match': 'synthetic-test-marker'}]}]}
        result = findings(report)
        self.assertEqual(result[1], ['SECRET'])
        self.assertNotIn('synthetic-test-marker', str(result))

    def test_unrecognized_or_eol_image_is_rejected(self):
        for metadata in [{}, {'OS': {'Family': 'debian', 'EOSL': True}}]:
            with self.assertRaises(ValueError):
                findings({'SchemaVersion': 2, 'Metadata': metadata, 'Results': []}, image=True)

    def test_lower_severity_is_visible(self):
        counts, blocked = findings({'SchemaVersion': 2, 'Results': [{'Vulnerabilities': [
            {'Severity': 'LOW'}, {'Severity': 'MEDIUM'}]}]})
        self.assertEqual(counts, {'LOW': 1, 'MEDIUM': 1})
        self.assertFalse(blocked)

    def test_insecure_lock_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'lock.json'
            images = read_lock()
            images['nextcloud'] = 'nextcloud:latest'
            path.write_text(json.dumps(images))
            with self.assertRaises(ValueError):
                read_lock(path)

    def test_gate_failure_never_reaches_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            stack = Stack(self.c, Path(tmp), Path(tmp) / 'audit')
            with patch('nextcloud.scan', side_effect=ValueError('blocked')), patch('nextcloud.run') as command:
                with self.assertRaises(ValueError):
                    stack.build()
                command.assert_not_called()
            self.assertFalse((Path(tmp) / 'build.json').exists())

    def test_no_published_ports_or_privileges(self):
        spec = compose(self.c, Path('/var/lib/nextcloud-stack'), read_lock(), 'sha256:' + 'a' * 64)
        for name, svc in spec['services'].items():
            with self.subTest(service=name):
                self.assertTrue(svc['read_only'])
                self.assertEqual(svc['cap_drop'], ['ALL'])
                self.assertNotIn('ports', svc)
                self.assertNotIn('privileged', svc)
                self.assertNotIn('network_mode', svc)
                self.assertNotEqual(svc['user'].split(':')[0], '0')
                self.assertIn('no-new-privileges:true', svc['security_opt'])
                self.assertEqual(svc['restart'], 'no')
        self.assertNotIn('admin_password', spec['services']['app']['secrets'])
        self.assertNotIn('front', spec['services']['db']['networks'])
        self.assertTrue(spec['networks']['back']['internal'])

    def test_proxy_does_not_trust_client_forwarding(self):
        conf = nginx_config(self.c)
        self.assertIn('proxy_set_header X-Forwarded-For $realip_remote_addr;', conf)
        self.assertNotIn('$proxy_add_x_forwarded_for', conf)
        self.assertIn('richdocumentscode', conf)
        self.assertNotIn('listen 80', conf)
        self.assertIn('TLSv1.2 TLSv1.3', conf)
        self.assertIn('listen 172.30.90.1:443 ssl;', conf)
        self.assertIn('if ($host != cloud.example.com)', conf)

    def test_firewall_scope_and_networks(self):
        conf = firewall(self.c)
        self.assertNotIn('\nflush ruleset', conf)
        self.assertNotIn('dnat', conf)
        self.assertIn('table bridge nextcloud_l2', conf)
        self.assertIn('169.254.0.0/16', conf)
        self.assertIn('ct state established', conf)
        self.assertNotIn('tcp dport { 80, 443 }', conf)

    def test_disabled_code_app_on_disk_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            info = Path(tmp) / 'apps/renamed/appinfo/info.xml'
            info.parent.mkdir(parents=True)
            info.write_text('<info><id>richdocumentscode</id></info>')
            with self.assertRaises(ValueError):
                Stack(self.c, Path(tmp), Path(tmp) / 'audit').reject_code_apps()


if __name__ == '__main__':
    unittest.main()
