import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from configuration import compose, php_config
from isolation import check_container, nft_structure, no_symlinks
from nextcloud import Stack, nginx_test
from security import findings, read_lock


class RegressionTests(unittest.TestCase):
    def setUp(self):
        self.c = json.loads((ROOT / 'site.example.json').read_text())

    def test_runtime_config_is_readonly_but_offline_admin_can_write(self):
        spec = compose(self.c, Path('/var/lib/nextcloud-stack'), read_lock(), 'sha256:' + 'a' * 64)
        for service, readonly in [('app', True), ('init', False)]:
            mount = next(m for m in spec['services'][service]['volumes'] if m['target'].endswith('/config'))
            self.assertEqual(mount['read_only'], readonly)
        self.assertNotIn('NC_CONFIG_WRITABLE', spec['services']['app']['environment'])
        self.assertIn("'localstorage.allowsymlinks' => false", php_config(self.c))

    def test_symlinked_state_and_backup_destination_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'actual').mkdir()
            (root / 'alias').symlink_to(root / 'actual', target_is_directory=True)
            with self.assertRaises(ValueError):
                no_symlinks(root / 'alias/new-file')
            stack = Stack(self.c, root / 'actual', root / 'audit')
            with patch('nextcloud.shutil.which', return_value='/bin/age'), self.assertRaises(ValueError):
                stack.backup(root / 'alias/backup.age', 'age1' + 'a' * 58)

    def test_render_does_not_destroy_installed_compose(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            (state / 'build.json').write_text('{}')
            (state / 'generated').mkdir()
            p = state / 'generated/compose.json'
            p.write_text('working-compose')
            result = subprocess.run([sys.executable, str(ROOT / 'scripts/nextcloud.py'),
                                     '--config', str(ROOT / 'site.example.json'), '--state', str(state), 'render'],
                                    capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(p.read_text(), 'working-compose')

    def test_partial_backup_removed_and_app_restored_on_encryption_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / 'state'
            state.mkdir()
            # Полный синтетический архив, без реальных паролей/данных.
            for name in ['config', 'data', 'apps', 'secrets', 'generated']:
                (state / name).mkdir()
            for name in ['site.json', 'build.json']:
                (state / name).write_text('{}')
            age = root / 'age'
            age.write_text('#!/bin/sh\nexit 7\n')
            age.chmod(0o700)
            stack = Stack(self.c, state, root / 'audit')
            calls = []
            def compose_fake(*args, **kwargs):
                calls.append(args)
                if 'stdout' in kwargs:
                    kwargs['stdout'].write(b'synthetic dump')
            with patch.dict(os.environ, {'PATH': str(root) + os.pathsep + os.environ['PATH']}), \
                    patch.object(stack, 'occ', return_value='{"installed":true}'), \
                    patch.object(stack, 'compose', side_effect=compose_fake), self.assertRaises(ValueError):
                stack.backup(root / 'backup.age', 'age1' + 'a' * 58)
            self.assertFalse((root / 'backup.age').exists())
            self.assertFalse(list(root.glob('.nextcloud-backup-*')))
            self.assertFalse(list(state.glob('backup-*')))
            self.assertIn(('run', '--rm', '--no-deps', '-T', 'init', '/srv/nextcloud/occ', 'maintenance:mode', '--off'), calls)
            self.assertEqual(calls[-1], ('up', '-d', '--wait', '--wait-timeout', '180', 'app'))

    def test_incomplete_scan_does_not_pass(self):
        report = {'SchemaVersion': 2, 'Metadata': {'OS': {'Family': 'debian'}},
                  'Results': [{'Class': 'secret', 'Secrets': []}]}
        with self.assertRaises(ValueError):
            findings(report, image=True)

    def test_occ_rewrite_keeps_config_private_without_following_links(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            (state / 'config').mkdir()
            config = state / 'config/config.php'
            config.touch(mode=0o640)
            config.chmod(0o640)
            stack = Stack(self.c, state, state / 'audit')
            with patch.object(stack, 'compose'):
                stack.offline_occ('maintenance:mode', '--off')
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
            target = state / 'unrelated'
            target.touch(mode=0o644)
            target.chmod(0o644)
            config.unlink()
            config.symlink_to(target)
            with patch.object(stack, 'compose'), self.assertRaises(ValueError):
                stack.offline_occ('status')
            self.assertEqual(target.stat().st_mode & 0o777, 0o644)

    def test_2fa_uses_offline_writable_config_and_recovers_after_error(self):
        for fail in [False, True]:
            with self.subTest(fail=fail), tempfile.TemporaryDirectory() as tmp:
                state = Path(tmp)
                (state / 'config').mkdir()
                (state / 'config/config.php').touch()
                stack = Stack(self.c, state, state / 'audit')
                with patch.object(stack, 'saved_build'), patch.object(stack, 'compose') as commands, \
                        patch.object(stack, 'offline_occ', side_effect=ValueError('failed') if fail else None) as admin:
                    if fail:
                        with self.assertRaises(ValueError):
                            stack.enforce_2fa()
                    else:
                        stack.enforce_2fa()
                    admin.assert_called_once_with('twofactorauth:enforce', '--on', capture=True)
                    self.assertEqual(commands.call_args_list[0].args, ('stop', '--timeout', '60', 'app'))
                    self.assertEqual(commands.call_args_list[-1].args, ('up', '-d', '--wait', '--wait-timeout', '180', 'app'))

    def test_nginx_conflict_warning_is_an_error_even_with_exit_zero(self):
        result = subprocess.CompletedProcess(['nginx'], 0, '', 'nginx: [warn] conflicting server name "cloud.test" ignored')
        with patch('nextcloud.subprocess.run', return_value=result), self.assertRaises(ValueError):
            nginx_test()

    def test_nginx_config_and_ordering_are_rolled_back_on_failed_reload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = copy.deepcopy(self.c)
            for key in ['certificate', 'certificate_key']:
                p = root / key
                p.touch()
                config[key] = str(p)
            state = root / 'state'
            (state / 'generated').mkdir(parents=True)
            (state / 'generated/nginx.conf').write_text('# nextcloud-stack: new\n')
            vhost = root / 'vhost'
            vhost.write_text('# nextcloud-stack: old\n')
            order = root / 'dropin/nextcloud-order.conf'
            paths = {'/etc/nginx/conf.d/nextcloud-stack.conf': vhost,
                     '/var/log/nginx/nextcloud-error.log': root / 'error.log',
                     '/etc/systemd/system/nginx.service.d/nextcloud-order.conf': order}
            def fake_run(args, **kw):
                if args == ['nginx', '-T']:
                    return ''
                if args == ['systemctl', 'reload', 'nginx']:
                    raise ValueError('synthetic reload failure')
                return 0
            stack = Stack(config, state, root / 'audit')
            with patch('nextcloud.Path', side_effect=lambda x: paths.get(str(x), Path(x))), \
                    patch.object(stack, 'saved_build'), patch('nextcloud.nginx_test'), \
                    patch('nextcloud.run', side_effect=fake_run), self.assertRaises(ValueError):
                stack.nginx()
            self.assertEqual(vhost.read_text(), '# nextcloud-stack: old\n')
            self.assertFalse(order.exists())

    def test_upgrade_without_schema_change_and_failure_recovery_marker(self):
        for needs_upgrade in [False, True]:
            with self.subTest(needs_upgrade=needs_upgrade), tempfile.TemporaryDirectory() as tmp:
                state = Path(tmp)
                (state / 'config').mkdir()
                (state / 'config/config.php').write_text('synthetic')
                (state / 'candidate.json').write_text('{"image":"new"}')
                (state / 'build.json').write_text('{"image":"old"}')
                stack = Stack(self.c, state, state / 'audit')
                calls = []
                def offline(*args, **kw):
                    calls.append(args)
                    if args[0] == 'status':
                        return json.dumps({'installed': True, 'needsDbUpgrade': needs_upgrade})
                    if args[0] == 'upgrade':
                        raise ValueError('migration failed')
                with patch('nextcloud.preflight'), patch.object(stack, 'build', return_value='new'), \
                        patch.object(stack, 'backup'), patch.object(stack, 'prepare'), \
                        patch.object(stack, 'compose') as commands, patch.object(stack, 'verify'), \
                        patch.object(stack, 'offline_occ', side_effect=offline):
                    if needs_upgrade:
                        with self.assertRaises(ValueError):
                            stack.upgrade('backup.age', 'recipient')
                        self.assertTrue((state / 'upgrade-in-progress').exists())
                        self.assertEqual(json.loads((state / 'build.json').read_text())['image'], 'old')
                        self.assertFalse(any(c.args[0] == 'up' for c in commands.call_args_list))
                        with self.assertRaises(ValueError):
                            stack.saved_build()
                    else:
                        stack.upgrade('backup.age', 'recipient')
                        self.assertNotIn(('upgrade',), calls)
                        self.assertFalse((state / 'upgrade-in-progress').exists())
                        self.assertEqual(json.loads((state / 'build.json').read_text())['image'], 'new')

    def test_firewall_comparison_ignores_counters_but_detects_allow_rule(self):
        original = {'nftables': [{'rule': {'handle': 4, 'expr': [{'counter': {'packets': 1, 'bytes': 60}}, {'drop': None}]}}]}
        changed = copy.deepcopy(original)
        changed['nftables'][0]['rule']['handle'] = 20
        changed['nftables'][0]['rule']['expr'][0]['counter']['packets'] = 15
        self.assertEqual(nft_structure(original), nft_structure(changed))
        changed['nftables'][0]['rule']['expr'][-1] = {'accept': None}
        self.assertNotEqual(nft_structure(original), nft_structure(changed))

    def test_actual_container_tampering_rejected(self):
        # docker inspect в JSON: проверяем именно обнаружение опасных отклонений.
        definition = compose(self.c, Path('/var/lib/nextcloud-stack'), read_lock(), 'sha256:' + 'a' * 64)
        spec = definition['services']['app']
        facts = {'Image': spec['image'], 'Config': {'User': '33:33', 'Env': ['NEXTCLOUD_CONFIG_DIR=/var/lib/nextcloud/config']},
                 'HostConfig': {'ReadonlyRootfs': True, 'CapDrop': ['ALL'], 'SecurityOpt': ['no-new-privileges:true'],
                                'RestartPolicy': {'Name': 'no'}, 'PidsLimit': 256, 'Memory': 3 * 1024**3,
                                'NanoCpus': 2 * 10**9, 'Sysctls': {'net.ipv6.conf.all.disable_ipv6': '1'},
                                'Tmpfs': dict(x.split(':', 1) for x in spec['tmpfs'])},
                 'Mounts': [{'Type': 'bind', 'Destination': m['target'], 'Source': m['source'], 'RW': not m['read_only']}
                            for m in spec['volumes']],
                 'NetworkSettings': {'Networks': {definition['networks'][n]['name']: {'IPAddress': v['ipv4_address']}
                                                 for n, v in spec['networks'].items()}}}
        facts['Mounts'].extend({'Type': 'bind', 'Destination': '/run/secrets/' + n,
                               'Source': definition['secrets'][n]['file'], 'RW': False} for n in spec['secrets'])
        check_container('app', facts, spec, definition, spec['image'])
        for key, value in [('CapAdd', ['NET_ADMIN']), ('SecurityOpt', ['seccomp=unconfined']),
                           ('ReadonlyRootfs', False), ('PortBindings', {'8080/tcp': [{'HostPort': '8080'}]}),
                           ('NetworkMode', 'host'), ('Memory', 0), ('PublishAllPorts', True)]:
            bad = copy.deepcopy(facts)
            bad['HostConfig'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                check_container('app', bad, spec, definition, spec['image'])
        for target in ['/etc', '/var/run/docker.sock']:
            bad = copy.deepcopy(facts)
            bad['Mounts'].append({'Type': 'bind', 'Source': target, 'Destination': target, 'RW': True})
            with self.subTest(target=target), self.assertRaises(ValueError):
                check_container('app', bad, spec, definition, spec['image'])
        bad = copy.deepcopy(facts)
        bad['Mounts'][0]['RW'] = True
        with self.assertRaises(ValueError):
            check_container('app', bad, spec, definition, spec['image'])


if __name__ == '__main__':
    unittest.main()
