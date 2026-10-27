"""Проверки завершаются отказом при ошибке, устаревшей БД или опасной находке."""
import collections
import datetime as dt
import json
import os
import platform
import re
import shutil
import subprocess
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read_lock(path=ROOT / 'images.lock.json'):
    images = json.loads(path.read_text())
    if set(images) != {'nextcloud', 'postgres', 'redis'}:
        raise ValueError('Неверный images.lock.json')
    for name, ref in images.items():
        if not re.fullmatch(r'docker.io/library/' + name + r':[a-zA-Z0-9_.-]+@sha256:[a-f0-9]{64}', ref):
            raise ValueError('Нужны официальные образы, закреплённые SHA256 digest')
    if not images['nextcloud'].startswith('docker.io/library/nextcloud:35.'):
        raise ValueError('Этот установщик рассчитан на Nextcloud 35; переход major требует проверки совместимости')
    if not images['postgres'].startswith('docker.io/library/postgres:17-'):
        raise ValueError('PostgreSQL major должен оставаться 17: изменение требует миграции')
    return images


def check_php(version):
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('Неизвестная/предварительная версия PHP')
    v = tuple(map(int, version.split('.')))
    minimum = {(8, 3): 36, (8, 4): 27, (8, 5): 12}
    if v[:2] not in minimum or v[2] < minimum[v[:2]]:
        raise ValueError('PHP не удовлетворяет минимуму исправлений CVE-2026-109618/109619')


def findings(report, image=False):
    if report.get('SchemaVersion') != 2:
        raise ValueError('Неизвестная схема отчёта Trivy')
    if image:
        meta = report.get('Metadata', {}).get('OS', {})
        if not meta.get('Family') or meta.get('EOSL'):
            raise ValueError('ОС образа не распознана или больше не поддерживается')
        if not report.get('Results'):
            raise ValueError('Образ не был просканирован')
    counts = collections.Counter()
    blocked = []
    for result in report.get('Results', []):
        for item in result.get('Vulnerabilities', []) or []:
            severity = item.get('Severity', 'UNKNOWN').upper()
            counts[severity] += 1
            if severity not in {'LOW', 'MEDIUM'}:
                blocked.append(item.get('VulnerabilityID', 'UNKNOWN'))
        for item in result.get('Secrets', []) or []:
            blocked.append('SECRET')  # Никогда не выводить Match из отчёта.
        for item in result.get('Misconfigurations', []) or []:
            if item.get('Status') == 'FAIL' and item.get('Severity', 'UNKNOWN').upper() not in {'LOW', 'MEDIUM'}:
                blocked.append(item.get('ID', 'CONFIG'))
    return dict(counts), blocked


def upstream(images, audit):
    request = urllib.request.Request(
        'https://raw.githubusercontent.com/nextcloud/docker/master/versions.json',
        headers={'User-Agent': 'civisrom-nextcloud-security-check'})
    with urllib.request.urlopen(request, timeout=45) as response:
        releases = json.load(response)
    (audit / 'upstream-versions.json').write_text(json.dumps(releases, indent=2))
    version = images['nextcloud'].split(':')[1].split('-apache@')[0]
    if releases.get('35', {}).get('version') != version:
        raise ValueError('Закреплённый Nextcloud не совпадает с актуальным выпуском ветки 35; обновите lock-файл')


def scan(audit, images, built=None, remote=True):
    audit = Path(audit)
    audit.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(audit, 0o700)
    if not shutil.which('trivy'):
        raise ValueError('Установите Trivy: sudo ./tools/install-trivy.sh')
    environment = {k: v for k, v in os.environ.items() if not k.startswith('TRIVY_')}
    version = json.loads(subprocess.check_output(['trivy', '--version', '--format', 'json'], env=environment))['Version']
    if not re.fullmatch(r'\d+\.\d+\.\d+', version) or tuple(map(int, version.split('.'))) < (0, 76, 1):
        raise ValueError('Обновите Trivy до версии не ниже 0.76.1')
    cache = audit.parent / 'trivy-cache'
    base = ['trivy', '--config', '/dev/null', '--cache-dir', str(cache)]
    def invoke(args, name):
        with (audit / (name + '.log')).open('wb') as log:
            result = subprocess.run(base + args, cwd=ROOT, env=environment, stdout=log, stderr=log)
        if result.returncode:
            raise ValueError(f'Ошибка Trivy ({name}); сборка запрещена. Журнал: {audit / (name + ".log")}')
    if built is None:
        upstream(images, audit)
        invoke(['image', '--download-db-only', '--no-progress'], 'database')
    metadata = json.loads((cache / 'db/metadata.json').read_text())
    updated = dt.datetime.fromisoformat(metadata['UpdatedAt'].replace('Z', '+00:00'))
    age = dt.datetime.now(dt.timezone.utc) - updated
    if age > dt.timedelta(hours=24) or age < -dt.timedelta(hours=1):
        raise ValueError('База CVE старше 24 часов или неверное системное время')
    platform_name = {'x86_64': 'linux/amd64', 'aarch64': 'linux/arm64'}.get(platform.machine())
    if platform_name is None:
        raise ValueError('Поддерживаются amd64/arm64')
    failures = []
    targets = {'built': built} if built else images
    for name, ref in targets.items():
        output = audit / (name + '.json')
        print(f'Проверка образа {name}…', flush=True)
        invoke(['image', '--image-src', 'remote' if remote and not built else 'docker',
                '--platform', platform_name, '--skip-db-update', '--no-progress', '--timeout', '20m',
                '--scanners', 'vuln,secret', '--ignorefile', '/dev/null',
                '--list-all-pkgs',
                '--format', 'json', '--output', str(output), ref], name)
        counts, denied = findings(json.loads(output.read_text()), image=True)
        invoke(['convert', '--format', 'cyclonedx', '--output', str(audit / (name + '.cdx.json')),
                str(output)], name + '-sbom')
        print(name + ': ' + json.dumps(counts) + f'; блокирующих находок: {len(denied)}')
        failures.extend(denied)
    if built is None:
        # Только публикуемые исходники. Локальный firewall/пароли не сканируются и не копируются.
        source = audit / 'source'
        source.mkdir(exist_ok=True)
        for name in ['Dockerfile', 'container', 'scripts', 'tools', 'install.sh', 'images.lock.json']:
            src = ROOT / name
            if src.is_dir():
                shutil.copytree(src, source / name, dirs_exist_ok=True, ignore=shutil.ignore_patterns('__pycache__'))
            else:
                shutil.copy2(src, source / name)
        output = audit / 'source.json'
        invoke(['fs', '--skip-db-update', '--no-progress', '--timeout', '10m',
                '--scanners', 'vuln,secret,misconfig', '--ignorefile', '/dev/null',
                '--format', 'json', '--output', str(output), str(source)], 'source')
        _, denied = findings(json.loads(output.read_text()))
        failures.extend(denied)
    if failures:
        raise ValueError(f'Проверка безопасности НЕ пройдена ({len(failures)} находок). '
                         f'Сборка/установка запрещена; отчёты только локально: {audit}')
    print('Проверка известных уязвимостей пройдена. Это не гарантия отсутствия неизвестных уязвимостей.')
