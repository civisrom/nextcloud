#!/usr/bin/env python3
"""Установка одного Nextcloud на хост с готовыми Docker, Nginx и ручным nftables."""
import argparse
import datetime as dt
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile

from configuration import compose, firewall, nginx_config, php_config, render, validate
from isolation import check_container, check_firewall, no_symlinks, private_directory
from security import ROOT, check_php, read_lock, scan


def run(args, capture=False, check=True, **kw):
    kw.setdefault('timeout', 1800)
    result = subprocess.run([str(x) for x in args], text=True, capture_output=capture, **kw)
    if check and result.returncode:
        # Не печатаем захваченный вывод: OCC и сторонние программы могут содержать секреты.
        raise ValueError(f'Команда {args[0]} завершилась с кодом {result.returncode}')
    return result.stdout.strip() if capture else result.returncode


def source_hash():
    h = hashlib.sha256()
    for p in sorted([ROOT / 'Dockerfile', ROOT / 'images.lock.json', ROOT / 'install.sh',
                     *(ROOT / 'container').iterdir(), *(ROOT / 'scripts').glob('*.py')]):
        if p.is_file():
            h.update(str(p.relative_to(ROOT)).encode() + b'\0' + p.read_bytes())
    return h.hexdigest()


def nginx_test():
    result = subprocess.run(['nginx', '-t'], capture_output=True, text=True, timeout=30)
    if result.returncode or 'conflicting server name' in result.stderr.lower():
        raise ValueError('Конфигурация Nginx неверна или содержит конфликт server_name')


def firewall_ready(c):
    check_firewall(firewall(c))


def preflight(c):
    if os.geteuid() != 0:
        raise ValueError('Для этой команды нужен root')
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if release.get('ID', '').strip('"') != 'ubuntu' or release.get('VERSION_ID', '').strip('"') not in {'24.04', '26.04'}:
        raise ValueError('Поддерживаются только Ubuntu 24.04 LTS и 26.04 LTS')
    for cmd in ['docker', 'nft', 'nginx', 'systemctl', 'ip', 'unshare']:
        if not shutil.which(cmd):
            raise ValueError('Не найден обязательный компонент: ' + cmd)
    if os.environ.get('DOCKER_HOST') or os.environ.get('DOCKER_CONTEXT'):
        raise ValueError('Нужен локальный Docker через стандартный socket; удалённый context запрещён')
    endpoint = json.loads(run(['docker', 'context', 'inspect'], capture=True))[0]['Endpoints']['docker']['Host']
    if endpoint != 'unix:///var/run/docker.sock':
        raise ValueError('Нестандартный Docker endpoint')
    info = json.loads(run(['docker', 'info', '--format', '{{json .}}'], capture=True))
    if any('rootless' in x or 'userns' in x for x in info['SecurityOptions']):
        raise ValueError('Эта схема UID/nftables требует rootful Docker без userns-remap')
    if not any('name=seccomp' in x and 'profile=builtin' in x for x in info['SecurityOptions']):
        raise ValueError('Нужен стандартный seccomp-профиль Docker')
    if not any('name=apparmor' in x for x in info['SecurityOptions']):
        raise ValueError('Для Ubuntu требуется включённый AppArmor Docker')
    daemon = json.loads(Path('/etc/docker/daemon.json').read_text())
    for key in ['iptables', 'ip6tables', 'userland-proxy']:
        if daemon.get(key) is not False:
            raise ValueError('В /etc/docker/daemon.json необходимо явно задать ' + key + ': false')
    pid = run(['systemctl', 'show', 'docker.service', '--property=MainPID', '--value'], capture=True)
    args = Path('/proc/' + pid + '/cmdline').read_bytes().split(b'\0')
    if any(x.startswith((b'--iptables', b'--ip6tables', b'--userland-proxy', b'--config-file')) for x in args):
        raise ValueError('Параметры firewall/config-file заданы в argv dockerd; устраните неоднозначность с daemon.json')
    if Path('/proc/sys/net/ipv4/ip_forward').read_text().strip() != '1':
        raise ValueError('Нужен net.ipv4.ip_forward=1; скрипт глобальные sysctl не меняет')
    if not Path('/sys/class/net', c['wan_interface']).exists():
        raise ValueError('Внешний интерфейс не найден')
    version = run(['docker', 'compose', 'version', '--short'], capture=True).lstrip('v')
    if not re.fullmatch(r'\d+\.\d+\.\d+', version) or tuple(map(int, version.split('.'))) < (2, 33, 1):
        raise ValueError('Нужен Docker Compose >=2.33.1 (gw_priority)')
    # Пересечение с чужими Docker/VPN/host-маршрутами недопустимо.
    wanted = [ipaddress.ip_network(c[k]) for k in ['frontend_subnet', 'backend_subnet']]
    for route in json.loads(run(['ip', '-j', '-4', 'route', 'show', 'table', 'all'], capture=True)):
        dst = route.get('dst', 'default')
        if dst == 'default' or route.get('dev') in {'br-nc-front', 'br-nc-back'}:
            continue
        if any(ipaddress.ip_network(dst, strict=False).overlaps(n) for n in wanted):
            raise ValueError('Подсети Nextcloud пересекаются с существующим маршрутом')
    firewall_ready(c)
    nginx_test()


class Stack:
    def __init__(self, c, state, audit):
        self.c, self.state, self.audit = c, state, audit
        self.images = read_lock()

    def compose(self, *args, **kw):
        return run(['docker', 'compose', '--project-name', 'nextcloud', '--file',
                    self.state / 'generated/compose.json', *args], **kw)

    def occ(self, *args, **kw):
        kw.setdefault('timeout', 180)
        return self.compose('exec', '-T', '--user', '33:33', 'app', 'php', 'occ', *args, **kw)

    def offline_occ(self, *args, **kw):
        # Вызывается только при остановленном app: init занимает те же IP.
        try:
            return self.compose('run', '--rm', '--no-deps', '-T', 'init', '/srv/nextcloud/occ', *args, **kw)
        finally:
            # Nextcloud при перезаписи config.php возвращает 0640. Для этого
            # профиля сохраняем 0600 после каждой административной операции.
            config = self.state / 'config/config.php'
            if config.exists() or config.is_symlink():
                no_symlinks(config)
                fd = os.open(config, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    os.fchmod(fd, 0o600)
                finally:
                    os.close(fd)

    def definition(self, image):
        return compose(self.c, self.state, self.images, image)

    def check_files(self, image):
        private_directory(self.state)
        for name, uid in [('config', 33), ('data', 33), ('apps', 33), ('postgres', 999),
                          ('secrets', 0), ('generated', 0)]:
            private_directory(self.state / name, owner=uid)
        for name in ['admin_password', 'db_password', 'postgres_password', 'redis_password']:
            p = self.state / 'secrets' / name
            no_symlinks(p)
            s = p.stat()
            if not p.is_file() or s.st_uid != 0 or s.st_mode & 0o777 != 0o444:
                raise ValueError('Неверные права secret: ' + name)
        config = self.state / 'config'
        for p in config.iterdir():
            no_symlinks(p)
            if p.name not in {'config.php', 'zz-security.config.php', '.htaccess'}:
                raise ValueError('Неожиданный файл в config: ' + p.name)
        p = config / 'config.php'
        if p.stat().st_uid != 33 or p.stat().st_mode & 0o777 != 0o600:
            raise ValueError('config.php должен принадлежать UID 33 и иметь права 0600')
        out = self.state / 'generated'
        expected = {'security.config.php': php_config(self.c), 'nginx.conf': nginx_config(self.c),
                    'nextcloud.nft': firewall(self.c),
                    **{n: (ROOT / 'container' / n).read_text() for n in ['init-db.sql', 'redis.sh']}}
        for name, content in expected.items():
            no_symlinks(out / name)
            if (out / name).read_text() != content:
                raise ValueError('Сгенерированный файл изменён: ' + name)
        no_symlinks(out / 'compose.json')
        if json.loads((out / 'compose.json').read_text()) != self.definition(image):
            raise ValueError('Compose отличается от проверенной конфигурации')

    def prepare(self, image):
        private_directory(self.state, create=True)
        for folder, uid in [('config', 33), ('data', 33), ('apps', 33), ('postgres', 999), ('secrets', 0)]:
            p = self.state / folder
            no_symlinks(p)
            p.mkdir(exist_ok=True, mode=0o700)
            os.chmod(p, 0o700)
            os.chown(p, uid, uid)
        for name in ['admin_password', 'db_password', 'postgres_password', 'redis_password']:
            p = self.state / 'secrets' / name
            no_symlinks(p)
            if not p.exists():
                if (self.state / 'config/config.php').exists():
                    raise ValueError('Потерян secret установленного экземпляра: ' + name)
                # Родитель 0700 root; 0444 позволяет прочитать отдельный bind mount разным UID.
                with p.open('x') as out:
                    out.write(secrets.token_hex(32))
                p.chmod(0o444)
        no_symlinks(self.state / 'generated')
        if (self.state / 'generated').exists():
            for p in (self.state / 'generated').iterdir():
                no_symlinks(p)
        out = render(self.c, self.state, self.images, image)
        out.chmod(0o700)
        for source in ['init-db.sql', 'redis.sh']:
            shutil.copy2(ROOT / 'container' / source, out / source)
        # Bind-mounted файлы доступны сервисам, родитель на хосте закрыт root-only.
        for p in out.iterdir():
            p.chmod(0o644)
        (self.state / 'site.json').write_text(json.dumps(self.c, indent=2) + '\n')
        self.compose('config', '--quiet')

    def build(self):
        scan(self.audit, self.images)
        for image in self.images.values():
            run(['docker', 'pull', image])
        version = run(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                       '--security-opt', 'no-new-privileges', '--entrypoint', 'php', self.images['nextcloud'],
                       '-r', 'echo PHP_VERSION;'], capture=True)
        check_php(version)
        postgres = run(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                        '--security-opt', 'no-new-privileges', '--entrypoint', 'postgres',
                        self.images['postgres'], '--version'], capture=True)
        if not re.fullmatch(r'postgres \(PostgreSQL\) 17\.\d+(?: .*)?', postgres):
            raise ValueError('Фактическая версия PostgreSQL не соответствует major 17')
        iid = self.audit / 'image-id'
        run(['docker', 'build', '--network=none', '--pull=false', '--iidfile', iid,
             '--build-arg', 'NEXTCLOUD_IMAGE=' + self.images['nextcloud'], ROOT])
        image = iid.read_text().strip()
        if not re.fullmatch(r'sha256:[a-f0-9]{64}', image):
            raise ValueError('Некорректный ID собранного образа')
        scan(self.audit, self.images, built=image, remote=False)
        probe = run(['docker', 'run', '--rm', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                     '--entrypoint', 'php', image, '-r',
                     'require "/srv/nextcloud/version.php"; '
                     'echo json_encode([PHP_VERSION, ini_get("session.upload_progress.enabled"), '
                     'glob("/srv/nextcloud/apps/richdocumentscode*"), $OC_VersionString]);'], capture=True)
        php_version, progress, code_apps, nc_version = json.loads(probe)
        check_php(php_version)
        if progress not in ['', '0'] or code_apps:
            raise ValueError('Опасная конфигурация PHP или обнаружен Built-in CODE Server')
        if nc_version != self.images['nextcloud'].split(':')[1].split('-apache@')[0]:
            raise ValueError('Фактическая версия Nextcloud не соответствует lock')
        self.state.mkdir(parents=True, exist_ok=True, mode=0o700)
        (self.state / 'candidate.json').write_text(json.dumps(
            {'image': image, 'source_hash': source_hash(), 'images': self.images,
             'checked_at': dt.datetime.now(dt.timezone.utc).isoformat()}, indent=2))
        return image

    def saved_build(self):
        if (self.state / 'upgrade-in-progress').exists():
            raise ValueError('Обновление не завершено; нужен проверенный restore, запуск заблокирован')
        data = json.loads((self.state / 'build.json').read_text())
        if data['source_hash'] != source_hash() or data['images'] != self.images:
            raise ValueError('Исходники/lock изменились; нужна новая проверка и сборка')
        image = run(['docker', 'image', 'inspect', '--format', '{{.Id}}', data['image']], capture=True)
        if image != data['image']:
            raise ValueError('Образ не совпадает с проверенным')
        if json.loads((self.state / 'site.json').read_text()) != self.c:
            raise ValueError('site.json изменился; согласуйте конфигурацию и firewall перед обновлением')
        self.check_files(image)
        return image

    def reject_code_apps(self):
        # Любое приложение вне проверенного образа обходит image scan, включая
        # отключённый/переименованный Built-in CODE Server. Содержимое не исполняем.
        if any((self.state / 'apps').iterdir()):
            raise ValueError('Непроверенные файлы в apps: дополнительные приложения должны входить в проверяемый образ')

    def start(self):
        preflight(self.c)
        self.saved_build()
        self.reject_code_apps()
        self.compose('up', '-d', '--wait', '--wait-timeout', '180', 'db', 'redis', 'app')
        self.verify()

    def verify(self):
        image = self.saved_build()
        firewall_ready(self.c)
        status = json.loads(self.occ('status', '--output=json', capture=True))
        if not status.get('installed') or status.get('maintenance') or status.get('needsDbUpgrade'):
            raise ValueError('Nextcloud не готов')
        if status.get('versionstring') != self.images['nextcloud'].split(':')[1].split('-apache@')[0]:
            raise ValueError('Запущена неожиданная версия Nextcloud')
        self.occ('integrity:check-core', capture=True)
        self.reject_code_apps()
        # Сами пароли/конфигурация в stdout не выводятся.
        role = self.compose('exec', '-T', 'db', 'psql', '-U', 'postgres', '-Atc',
                            "SELECT rolsuper OR rolcreatedb OR rolcreaterole OR rolreplication OR rolbypassrls "
                            "OR EXISTS (SELECT 1 FROM pg_auth_members WHERE member=pg_roles.oid) "
                            "FROM pg_roles WHERE rolname='nextcloud'", capture=True)
        if role != 'f':
            raise ValueError('У роли Nextcloud лишние права PostgreSQL')
        definition = self.definition(image)
        ids = {}
        for service in ['app', 'db', 'redis']:
            cid = self.compose('ps', '-q', service, capture=True)
            ids[service] = cid
            facts = json.loads(run(['docker', 'inspect', cid], capture=True))[0]
            spec = definition['services'][service]
            expected_image = run(['docker', 'image', 'inspect', '--format', '{{.Id}}', spec['image']], capture=True)
            check_container(service, facts, spec, definition, expected_image)
            if facts.get('AppArmorProfile') != 'docker-default':
                raise ValueError('Отключён стандартный AppArmor: ' + service)
            process = self.compose('exec', '-T', service, 'cat', '/proc/self/status', capture=True)
            values = dict(line.split(':', 1) for line in process.splitlines() if ':' in line)
            if int(values['CapEff'].strip(), 16) or values['NoNewPrivs'].strip() != '1' or values['Seccomp'].strip() != '2':
                raise ValueError('Фактические ограничения процесса не действуют: ' + service)
        for name, spec in definition['networks'].items():
            actual = json.loads(run(['docker', 'network', 'inspect', spec['name']], capture=True))[0]
            members = {ids[n] for n in ids if name in definition['services'][n]['networks']}
            if actual['Driver'] != 'bridge' or actual['Internal'] != spec['internal'] or actual['EnableIPv6'] \
                    or set(actual['Containers']) != members \
                    or {x['Subnet'] for x in actual['IPAM']['Config']} != {spec['ipam']['config'][0]['subnet']} \
                    or any(actual['Options'].get(k) != v for k, v in spec['driver_opts'].items()):
                raise ValueError('Нарушена изоляция Docker-сети: ' + name)
        print('Nextcloud готов; целостность ядра, права БД и изоляция контейнеров проверены.')

    def install(self):
        preflight(self.c)
        if (self.state / 'config/config.php').exists():
            raise ValueError('Nextcloud уже установлен; используйте start или upgrade')
        image = self.build()
        self.prepare(image)
        shutil.copy2(self.state / 'candidate.json', self.state / 'build.json')
        self.compose('up', '-d', '--wait', '--wait-timeout', '120', 'db', 'redis')
        self.compose('run', '--rm', '--no-deps', '-T', 'init', capture=True)
        self.offline_occ('background:cron', capture=True)
        self.offline_occ('app:enable', 'twofactor_totp', capture=True)
        self.offline_occ('app:enable', 'password_policy', capture=True)
        self.offline_occ('config:app:set', 'password_policy', 'minLength', '--value=14', capture=True)
        self.offline_occ('config:app:set', 'files', 'default_quota', '--value=10 GB', capture=True)
        self.offline_occ('config:app:set', 'core', 'shareapi_allow_links', '--value=no', capture=True)
        self.offline_occ('config:app:set', 'core', 'shareapi_allow_public_upload', '--value=no', capture=True)
        self.offline_occ('config:app:set', 'core', 'shareapi_allow_resharing', '--value=no', capture=True)
        (self.state / 'config/config.php').chmod(0o600)
        self.compose('up', '-d', '--wait', '--wait-timeout', '180', 'app')
        self.verify()
        self.units()
        print('Установка завершена. Пароль администратора хранится в secrets/admin_password (не выводится).')
        print('Войдите через HTTPS, настройте TOTP и recovery codes, затем выполните enforce-2fa.')

    def upgrade(self, destination, recipient):
        preflight(self.c)
        image = self.build()  # Отказ проверки не останавливает работающий экземпляр.
        self.backup(destination, recipient)
        self.compose('stop', '--timeout', '60', 'app')
        self.offline_occ('maintenance:mode', '--on', capture=True)
        marker = self.state / 'upgrade-in-progress'
        marker.write_text('При ошибке восстановите согласованный backup БД и данных.\n')
        self.prepare(image)
        status = json.loads(self.offline_occ('status', '--output=json', capture=True))
        if not status.get('installed') or type(status.get('needsDbUpgrade')) is not bool:
            raise ValueError('Обновление требует установленного Nextcloud')
        # При пересборке PHP/OS без смены версии Nextcloud миграция не требуется.
        # occ upgrade в maintenance без миграции возвращает ошибку 2.
        if status.get('needsDbUpgrade'):
            self.offline_occ('upgrade', capture=True)
        self.offline_occ('maintenance:mode', '--off', capture=True)
        (self.state / 'config/config.php').chmod(0o600)
        shutil.copy2(self.state / 'candidate.json', self.state / 'build.json')
        marker.unlink()
        self.compose('up', '-d', '--wait', '--wait-timeout', '180', 'app')
        self.verify()
        print('Обновление завершено. При ошибке миграции нужен полный restore; downgrade БД запрещён.')

    def enforce_2fa(self):
        self.saved_build()
        try:
            self.compose('stop', '--timeout', '60', 'app')
            self.offline_occ('twofactorauth:enforce', '--on', capture=True)
            (self.state / 'config/config.php').chmod(0o600)
        finally:
            self.compose('up', '-d', '--wait', '--wait-timeout', '180', 'app')

    def units(self):
        command = f'{ROOT}/install.sh --config {self.state}/site.json --state {self.state}'
        files = {
            'nextcloud-stack.service': f'''[Unit]
Description=Nextcloud Docker stack
Requires=docker.service
After=docker.service nftables.service network-online.target
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart={command} start
ExecStop={command} stop
TimeoutStartSec=600
TimeoutStopSec=180
[Install]
WantedBy=multi-user.target
''',
            'nextcloud-cron.service': f'''[Unit]
Description=Nextcloud background jobs
After=nextcloud-stack.service
[Service]
Type=oneshot
ExecStart={command} cron
''',
            'nextcloud-cron.timer': '''[Unit]
Description=Nextcloud cron every five minutes
[Timer]
OnBootSec=5m
OnUnitActiveSec=5m
Persistent=true
[Install]
WantedBy=timers.target
''',
            'nextcloud-security.service': f'''[Unit]
Description=Nextcloud vulnerability check (inspect failures in journal)
After=network-online.target
[Service]
Type=oneshot
ExecStart={command} scan
Nice=10
IOSchedulingClass=idle
''',
            'nextcloud-security.timer': '''[Unit]
Description=Daily Nextcloud security check
[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true
[Install]
WantedBy=timers.target
'''}
        marker = '# nextcloud-stack: managed by install.sh\n'
        for name in files:
            path = Path('/etc/systemd/system') / name
            no_symlinks(path)
            if path.exists() and not path.read_text().startswith(marker):
                raise ValueError('Имя unit уже занято: ' + name)
        for name, content in files.items():
            path = Path('/etc/systemd/system') / name
            path.write_text(marker + content)
            path.chmod(0o644)
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', 'nextcloud-stack.service'])
        run(['systemctl', 'enable', '--now', 'nextcloud-cron.timer', 'nextcloud-security.timer'])

    def nginx(self):
        self.saved_build()
        for key in ['certificate', 'certificate_key']:
            if not Path(self.c[key]).is_file():
                raise ValueError('Нужны существующий сертификат и ключ (например, ACME DNS-01)')
        path = Path('/etc/nginx/conf.d/nextcloud-stack.conf')
        no_symlinks(path)
        old = path.read_bytes() if path.exists() else None
        if old is not None and not old.startswith(b'# nextcloud-stack:'):
            raise ValueError('Имя конфигурации Nginx занято другим сайтом')
        # Поиск дубля домена без вывода конфигурации (там могут быть чувствительные строки).
        current = run(['nginx', '-T'], capture=True)
        if old is None and re.search(r'\bserver_name\s+[^;]*\b' + re.escape(self.c['domain']) + r'\s*[; ]', current):
            raise ValueError('Домен уже используется в Nginx; объедините vhost вручную')
        log = Path('/var/log/nginx/nextcloud-error.log')
        no_symlinks(log)
        log.touch(mode=0o600, exist_ok=True)
        log.chmod(0o600)
        # Listener на Docker gateway требует создания мостов до запуска Nginx.
        order = Path('/etc/systemd/system/nginx.service.d/nextcloud-order.conf')
        no_symlinks(order)
        previous_order = order.read_bytes() if order.exists() else None
        if previous_order is not None and not previous_order.startswith(b'# nextcloud-stack:'):
            raise ValueError('Имя drop-in Nginx занято другой конфигурацией')
        order.parent.mkdir(parents=True, exist_ok=True)
        try:
            order.write_text('# nextcloud-stack: Docker creates the gateway before Nginx binds it\n'
                             '[Unit]\nWants=docker.service\nAfter=docker.service\n')
            order.chmod(0o644)
            path.write_bytes((self.state / 'generated/nginx.conf').read_bytes())
            path.chmod(0o644)
            nginx_test()
            run(['systemctl', 'daemon-reload'])
            run(['systemctl', 'reload', 'nginx'])
        except Exception:
            if old is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(old)
            if previous_order is None:
                order.unlink(missing_ok=True)
            else:
                order.write_bytes(previous_order)
            run(['systemctl', 'daemon-reload'])
            raise
        print('Отдельный vhost Nginx установлен; остальные сайты не изменены.')

    def backup(self, destination, recipient):
        if not shutil.which('age') or not re.fullmatch(r'age1[a-z0-9]{58}', recipient or ''):
            raise ValueError('Для зашифрованного backup нужны age и публичный --recipient age1…')
        destination = Path(destination).absolute()
        no_symlinks(destination)
        if destination.exists() or destination.is_relative_to(self.state):
            raise ValueError('Backup должен быть новым файлом за пределами state')
        status = json.loads(self.occ('status', '--output=json', capture=True))
        if not status.get('installed') or status.get('maintenance') or status.get('needsDbUpgrade'):
            raise ValueError('Backup требует готовый экземпляр без уже включённого maintenance/миграции')
        stopped = False
        try:
            self.compose('stop', '--timeout', '60', 'app')
            stopped = True
            self.offline_occ('maintenance:mode', '--on', capture=True)
            with tempfile.TemporaryDirectory(dir=self.state, prefix='backup-') as temp:
                dump = Path(temp) / 'database.dump'
                with dump.open('wb') as stream:
                    self.compose('exec', '-T', 'db', 'pg_dump', '-U', 'postgres',
                                 '--format=custom', 'nextcloud', stdout=stream)
                with tempfile.NamedTemporaryFile(dir=destination.parent, prefix='.nextcloud-backup-') as output:
                    tar = subprocess.Popen(['tar', '--numeric-owner', '-C', str(self.state), '-czf', '-',
                                            'config', 'data', 'apps', 'secrets', 'generated', 'site.json', 'build.json',
                                            '-C', temp, 'database.dump'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                    try:
                        assert tar.stdout is not None
                        encrypted = subprocess.run(['age', '-r', recipient], stdin=tar.stdout,
                                                   stdout=output, stderr=subprocess.DEVNULL)
                        tar.stdout.close()
                        code = tar.wait()
                        if code or encrypted.returncode:
                            raise ValueError('Backup не завершён; неполный файл удалён')
                        output.flush()
                        os.fsync(output.fileno())
                        os.link(output.name, destination)  # Атомарно; существующий backup не перезаписывается.
                    finally:
                        if tar.poll() is None:
                            tar.terminate()
                            tar.wait(timeout=30)
            print('Зашифрованный backup создан. Храните копию вне сервера и проверяйте восстановление.')
        finally:
            if stopped:
                self.offline_occ('maintenance:mode', '--off', capture=True)
            self.compose('up', '-d', '--wait', '--wait-timeout', '180', 'app')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, default=Path('/etc/nextcloud-stack/site.json'))
    parser.add_argument('--state', type=Path, default=Path('/var/lib/nextcloud-stack'))
    parser.add_argument('--audit-dir', type=Path, default=Path('/var/log/nextcloud-security'))
    parser.add_argument('command', choices=['render', 'preflight', 'scan', 'build', 'install', 'start',
                                          'stop', 'verify', 'nginx', 'cron', 'enforce-2fa', 'backup', 'upgrade',
                                          'enable-services'])
    parser.add_argument('--destination')
    parser.add_argument('--recipient')
    args = parser.parse_args()
    os.umask(0o077)
    c = validate(json.loads(args.config.read_text()))
    state = args.state.absolute()
    for path in [state, args.config.absolute(), ROOT]:
        if not re.fullmatch(r'/[a-zA-Z0-9_./-]+', str(path)) or '..' in path.parts:
            raise ValueError('Пути должны быть абсолютными, без пробелов/спецсимволов/..')
    if len(state.parts) < 3 or state.is_relative_to(ROOT) or ROOT.is_relative_to(state):
        raise ValueError('State должен быть отдельным каталогом вне репозитория')
    no_symlinks(state)
    private_directory(state, create=True, owner=os.geteuid())
    if args.command == 'render':
        if (state / 'build.json').exists() or (state / 'config/config.php').exists():
            raise ValueError('render разрешён только до установки: он не должен затирать рабочий Compose')
        no_symlinks(state / 'generated')
        if (state / 'generated').exists():
            for p in (state / 'generated').iterdir():
                no_symlinks(p)
        print(render(c, state, read_lock()))
        return
    audit = args.audit_dir.absolute() / dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S-%f')
    if audit.resolve().is_relative_to(ROOT) or audit.resolve().is_relative_to(state):
        raise ValueError('Отчёты должны храниться вне репозитория')
    stack = Stack(c, state, audit)
    if args.command == 'scan':
        scan(audit, stack.images)
        if (state / 'build.json').exists():
            scan(audit, stack.images, built=stack.saved_build(), remote=False)
        return
    if os.geteuid() != 0:
        raise ValueError('Для этой команды нужен root')
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    no_symlinks(state / '.lock')
    with (state / '.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        cmd = args.command
        if cmd == 'preflight':
            preflight(c)
        elif cmd == 'build':
            stack.build()
        elif cmd == 'install':
            stack.install()
        elif cmd == 'start':
            stack.start()
        elif cmd == 'stop':
            stack.compose('stop', '--timeout', '60')
        elif cmd == 'verify':
            stack.verify()
        elif cmd == 'nginx':
            stack.nginx()
        elif cmd == 'cron':
            stack.compose('exec', '-T', '--user', '33:33', 'app', 'php', '-f', '/srv/nextcloud/cron.php', capture=True)
        elif cmd == 'enforce-2fa':
            stack.enforce_2fa()
        elif cmd == 'enable-services':
            preflight(c)
            stack.saved_build()
            stack.verify()
            stack.units()
        elif cmd == 'backup':
            if not args.destination:
                raise ValueError('Укажите --destination /путь/backup.tar.gz.age')
            stack.backup(args.destination, args.recipient)
        elif cmd == 'upgrade':
            if not args.destination or not args.recipient:
                raise ValueError('Обновление требует --destination и --recipient для предварительного backup')
            stack.upgrade(args.destination, args.recipient)
    # Unit вызывает start; запускать после освобождения общей блокировки.
    if args.command in {'install', 'enable-services'}:
        run(['systemctl', 'start', 'nextcloud-stack.service'])


if __name__ == '__main__':
    try:
        main()
    except subprocess.TimeoutExpired:
        print('ОШИБКА: превышен срок ожидания команды; проверьте состояние служб.', file=sys.stderr)
        sys.exit(1)
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as error:
        print('ОШИБКА: ' + str(error), file=sys.stderr)
        sys.exit(1)
