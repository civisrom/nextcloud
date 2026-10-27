"""Валидация входных данных и генерация конфигурации без побочных действий."""
import ipaddress
import json
import re
from pathlib import Path


def validate(c):
    required = {'domain', 'admin_user', 'wan_interface', 'frontend_subnet',
                'backend_subnet', 'dns', 'certificate', 'certificate_key',
                'default_phone_region', 'maintenance_window_start'}
    if set(c) != required:
        raise ValueError('Неверный набор полей site.json; сверьтесь с site.example.json')
    if not isinstance(c['domain'], str) or not re.fullmatch(
            r'(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+'
            r'[a-z]{2,63}', c['domain']):
        raise ValueError('Нужен DNS-домен в нижнем регистре, без URL/порта/wildcard')
    for key, pattern in [('admin_user', r'[a-zA-Z][a-zA-Z0-9_.-]{2,63}'),
                         ('wan_interface', r'[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}'),
                         ('default_phone_region', r'[A-Z]{2}')]:
        if not isinstance(c[key], str) or not re.fullmatch(pattern, c[key]):
            raise ValueError('Недопустимое значение: ' + key)
    if c['wan_interface'] in {'lo', 'br-nc-front', 'br-nc-back'}:
        raise ValueError('Неверный внешний интерфейс')
    for key in ['certificate', 'certificate_key']:
        if not re.fullmatch(r'/[a-zA-Z0-9_./-]+', c[key]) or '..' in Path(c[key]).parts:
            raise ValueError('Небезопасный путь сертификата')
    private = [ipaddress.ip_network(n) for n in ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']]
    nets = [ipaddress.ip_network(c[k], strict=True) for k in ['frontend_subnet', 'backend_subnet']]
    if any(n.version != 4 or n.prefixlen != 28 or not any(n.subnet_of(p) for p in private) for n in nets):
        raise ValueError('Сети должны быть непересекающимися частными IPv4 /28')
    if nets[0].overlaps(nets[1]):
        raise ValueError('Подсети пересекаются')
    if not isinstance(c['dns'], list) or not 1 <= len(c['dns']) <= 3:
        raise ValueError('Укажите 1–3 публичных DNS IPv4')
    for value in c['dns']:
        ip = ipaddress.ip_address(value)
        if ip.version != 4 or not ip.is_global or ip.is_multicast:
            raise ValueError('DNS должен быть публичным IPv4')
    if type(c['maintenance_window_start']) is not int or not 0 <= c['maintenance_window_start'] <= 23:
        raise ValueError('Окно обслуживания: целый час UTC 0–23')
    return c


def addresses(c):
    front, back = [ipaddress.ip_network(c[k]) for k in ['frontend_subnet', 'backend_subnet']]
    return {'gateway': str(front[1]), 'app': str(front[2]), 'app_back': str(back[2]),
            'db': str(back[3]), 'redis': str(back[4])}


def php_config(c):
    a = addresses(c)
    return r'''<?php
$CONFIG = [
    'trusted_domains' => ['DOMAIN'],
    'trusted_proxies' => ['GATEWAY'],
    'forwarded_for_headers' => ['HTTP_X_FORWARDED_FOR'],
    'overwriteprotocol' => 'https',
    'overwritehost' => 'DOMAIN',
    'overwrite.cli.url' => 'https://DOMAIN',
    'overwritecondaddr' => '^GATEWAY_REGEX$',
    'datadirectory' => '/var/lib/nextcloud/data',
    'memcache.local' => '\OC\Memcache\APCu',
    'memcache.distributed' => '\OC\Memcache\Redis',
    'memcache.locking' => '\OC\Memcache\Redis',
    'redis' => ['host' => 'redis', 'port' => 6379,
                'password' => trim(file_get_contents('/run/secrets/redis_password'))],
    'filelocking.enabled' => true,
    'auth.bruteforce.protection.enabled' => true,
    'auth.webauthn.enabled' => true,
    'auth.storeCryptedPassword' => false,
    'ratelimit.protection.enabled' => true,
    'allow_local_remote_servers' => false,
    'check_data_directory_permissions' => true,
    'debug' => false,
    'loglevel' => 2,
    'log_type' => 'file',
    'logfile' => '/var/lib/nextcloud/data/nextcloud.log',
    'log_rotate_size' => 10485760,
    'logtimezone' => 'UTC',
    'default_phone_region' => 'REGION',
    'maintenance_window_start' => WINDOW,
    'session_lifetime' => 3600,
    'session_keepalive' => false,
    'remember_login_cookie_lifetime' => 86400,
    'lost_password_link' => 'disabled',
    'appstoreenabled' => false,
    'upgrade.disable-web' => true,
    'apps_paths' => [
        ['path' => '/srv/nextcloud/apps', 'url' => '/apps', 'writable' => false],
        ['path' => '/var/lib/nextcloud/apps', 'url' => '/custom_apps', 'writable' => false],
    ],
    'enable_previews' => false,
    'sharing.enable_share_mail' => false,
    'share_folder' => '/Shared',
];
'''.replace('GATEWAY_REGEX', a['gateway'].replace('.', r'\.')).replace(
        'GATEWAY', a['gateway']).replace('DOMAIN', c['domain']).replace(
        'REGION', c['default_phone_region']).replace('WINDOW', str(c['maintenance_window_start']))


def nginx_config(c):
    a = addresses(c)
    # На relay порт 80 закрыт; сертификат предоставляет администратор (DNS-01).
    return rf'''# nextcloud-stack: отдельный vhost, nginx на хосте.
server {{
    listen 443 ssl;
    # Отдельный адрес для self-check: другие wildcard-vhost сюда не попадают.
    listen {a['gateway']}:443 ssl;
    server_name {c['domain']};
    if ($host != {c['domain']}) {{ return 444; }}
    ssl_certificate {c['certificate']};
    ssl_certificate_key {c['certificate_key']};
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_tickets off;
    ssl_session_cache shared:NextcloudTLS:10m;
    server_tokens off;
    client_max_body_size 1g;
    client_body_timeout 300s;
    send_timeout 300s;
    add_header Strict-Transport-Security "max-age=15552000" always;
    # Nextcloud сам выставляет CSP/COOP/X-Frame-Options — не заменять их.
    access_log off;
    error_log /var/log/nginx/nextcloud-error.log warn;
    location = /.well-known/carddav {{ return 301 https://{c['domain']}/remote.php/dav/; }}
    location = /.well-known/caldav {{ return 301 https://{c['domain']}/remote.php/dav/; }}
    location = /.well-known/webfinger {{ return 301 /index.php/.well-known/webfinger; }}
    location = /.well-known/nodeinfo {{ return 301 /index.php/.well-known/nodeinfo; }}
    location ~ ^/(?:config|data|lib|3rdparty|templates|tests|build)(?:/|$) {{ return 404; }}
    location ~ ^/(?:occ|console\.php|autotest|issue|indie|db_|\.)(?:.*)$ {{ return 404; }}
    # CVE-2026-110447: отключение приложения не закрывает прямой proxy.php.
    location ~* ^/(?:apps|custom_apps)/richdocumentscode(?:_arm64)?(?:/|$) {{ return 404; }}
    location / {{
        proxy_pass http://{a['app']}:8080;
        proxy_bind {a['gateway']};
        proxy_http_version 1.1;
        proxy_set_header Host {c['domain']};
        proxy_set_header X-Forwarded-Host {c['domain']};
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $realip_remote_addr;
        proxy_set_header X-Real-IP $realip_remote_addr;
        proxy_set_header Forwarded "";
        proxy_set_header Connection "";
        proxy_request_buffering off;
        proxy_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_connect_timeout 10s;
    }}
}}
'''


def filter_rules(c):
    """Те же ограниченные правила для отдельной таблицы и вставки в relay."""
    a = addresses(c)
    wan = c['wan_interface']
    dns = ', '.join(c['dns'])
    front, back = c['frontend_subnet'], c['backend_subnet']
    blocked = '0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4'
    internal = f'''iifname "br-nc-back" oifname "br-nc-back" ip saddr {a['app_back']} ip daddr {a['db']} tcp dport 5432 counter accept
        iifname "br-nc-back" oifname "br-nc-back" ip saddr {a['app_back']} ip daddr {a['redis']} tcp dport 6379 counter accept
        iifname "br-nc-back" oifname "br-nc-back" ip saddr {a['db']} ip daddr {a['app_back']} tcp sport 5432 ct state established counter accept
        iifname "br-nc-back" oifname "br-nc-back" ip saddr {a['redis']} ip daddr {a['app_back']} tcp sport 6379 ct state established counter accept'''
    return {
        'input': f'''iifname "br-nc-front" ip saddr != {a['app']} counter drop
        iifname {{ "br-nc-front", "br-nc-back" }} ct state invalid counter drop
        iifname "br-nc-front" ip saddr {a['app']} ct state established,related counter accept
        iifname "br-nc-front" ip saddr {a['app']} ip daddr {a['gateway']} tcp dport 443 counter accept
        iifname {{ "br-nc-front", "br-nc-back" }} counter drop''',
        'output': f'''oifname {{ "br-nc-front", "br-nc-back" }} ct state invalid counter drop
        oifname "br-nc-front" ip daddr {a['app']} ct state established,related counter accept
        oifname "br-nc-front" ip saddr {a['gateway']} ip daddr {a['app']} tcp dport 8080 counter accept
        oifname {{ "br-nc-front", "br-nc-back" }} counter drop''',
        'forward': f'''iifname {{ "br-nc-front", "br-nc-back" }} ct state invalid counter drop
        oifname {{ "br-nc-front", "br-nc-back" }} ct state invalid counter drop
        {internal}
        iifname "br-nc-back" counter drop
        oifname "br-nc-back" counter drop
        iifname "br-nc-front" ip saddr != {a['app']} counter drop
        iifname "br-nc-front" ip daddr {{ {blocked} }} counter drop
        iifname "br-nc-front" oifname "{wan}" ip saddr {a['app']} tcp dport 443 counter accept
        iifname "br-nc-front" oifname "{wan}" ip saddr {a['app']} ip daddr {{ {dns} }} meta l4proto {{ tcp, udp }} th dport 53 counter accept
        iifname "{wan}" oifname "br-nc-front" ip daddr {a['app']} ct state established,related counter accept
        iifname "br-nc-front" counter drop
        oifname "br-nc-front" counter drop
        ip saddr {{ {front}, {back} }} counter drop
        ip daddr {{ {front}, {back} }} counter drop''',
    }


def firewall(c):
    a = addresses(c)
    rules = filter_rules(c)
    chains = '\n'.join(f'''    chain {name} {{
        type filter hook {name} priority -20; policy accept;
        {rules[name]}
    }}''' for name in rules)
    return f'''# nextcloud-stack: НЕ содержит flush ruleset; загружать вместе с основным firewall.
# В других base chain с policy drop нужны соответствующие разрешения.
table inet nextcloud {{
    comment "nextcloud-stack"
{chains}
}}
table ip nextcloud_nat {{
    chain postrouting {{
        type nat hook postrouting priority 110; policy accept;
        oifname "{c['wan_interface']}" ip saddr {a['app']} masquerade
    }}
}}
table bridge nextcloud_l2 {{
    chain forward {{
        type filter hook forward priority -20; policy accept;
        meta ibrname "br-nc-back" meta obrname "br-nc-back" ether type arp counter accept
        meta ibrname "br-nc-back" meta obrname "br-nc-back" ip saddr {a['app_back']} ip daddr {a['db']} tcp dport 5432 counter accept
        meta ibrname "br-nc-back" meta obrname "br-nc-back" ip saddr {a['app_back']} ip daddr {a['redis']} tcp dport 6379 counter accept
        meta ibrname "br-nc-back" meta obrname "br-nc-back" ip saddr {a['db']} ip daddr {a['app_back']} tcp sport 5432 ct state established counter accept
        meta ibrname "br-nc-back" meta obrname "br-nc-back" ip saddr {a['redis']} ip daddr {a['app_back']} tcp sport 6379 ct state established counter accept
        meta ibrname {{ "br-nc-front", "br-nc-back" }} counter drop
        meta obrname {{ "br-nc-front", "br-nc-back" }} counter drop
    }}
}}
'''


def compose(c, state, images, app_image):
    a = addresses(c)
    state = str(state)
    def mount(source, target, ro=False):
        return {'type': 'bind', 'source': state + '/' + source, 'target': target,
                'read_only': ro, 'bind': {'create_host_path': False}}
    common = {'restart': 'no', 'read_only': True, 'cap_drop': ['ALL'],
              'security_opt': ['no-new-privileges:true'], 'pids_limit': 256,
              'logging': {'driver': 'local', 'options': {'max-size': '10m', 'max-file': '3'}},
              'sysctls': {'net.ipv6.conf.all.disable_ipv6': '1'}, 'pull_policy': 'never'}
    app = {**common, 'image': app_image, 'user': '33:33', 'init': True,
           'mem_limit': '3g', 'cpus': 2, 'dns': c['dns'],
           'tmpfs': ['/tmp:rw,noexec,nosuid,size=512m,uid=33,gid=33,mode=1770',
                     '/var/www/html:ro,noexec,nosuid,size=1m,mode=0555',
                     '/var/run/apache2:rw,noexec,nosuid,size=16m,uid=33,gid=33',
                     '/var/lock/apache2:rw,noexec,nosuid,size=16m,uid=33,gid=33'],
           'environment': {'NC_DOMAIN': c['domain'], 'NC_ADMIN_USER': c['admin_user']},
           'extra_hosts': {c['domain']: a['gateway']},
           'secrets': ['db_password', 'redis_password'],
           'volumes': [mount('config', '/var/lib/nextcloud/config'),
                       mount('apps', '/var/lib/nextcloud/apps', True),
                       mount('data', '/var/lib/nextcloud/data'),
                       mount('generated/security.config.php', '/var/lib/nextcloud/config/zz-security.config.php', True)],
           'networks': {'front': {'ipv4_address': a['app'], 'gw_priority': 1},
                        'back': {'ipv4_address': a['app_back']}},
           'depends_on': {'db': {'condition': 'service_healthy'}, 'redis': {'condition': 'service_healthy'}}}
    init = {**app, 'profiles': ['tools'], 'entrypoint': ['php'],
            'command': ['/opt/nextcloud/install.php'], 'healthcheck': {'disable': True},
            'secrets': ['db_password', 'redis_password', 'admin_password']}
    return {'name': 'nextcloud', 'services': {
        'app': app, 'init': init,
        'db': {**common, 'image': images['postgres'], 'user': '999:999', 'mem_limit': '2g', 'cpus': 2,
               'environment': {'POSTGRES_USER': 'postgres', 'POSTGRES_DB': 'postgres',
                               'POSTGRES_PASSWORD_FILE': '/run/secrets/postgres_password',
                               'POSTGRES_INITDB_ARGS': '--auth-host=scram-sha-256 --auth-local=peer'},
               'secrets': ['postgres_password', 'db_password'],
               'tmpfs': ['/tmp:rw,noexec,nosuid,size=128m,uid=999,gid=999',
                         '/var/run/postgresql:rw,noexec,nosuid,size=16m,uid=999,gid=999'],
               'volumes': [mount('postgres', '/var/lib/postgresql/data'),
                           mount('generated/init-db.sql', '/docker-entrypoint-initdb.d/10-nextcloud.sql', True)],
               'networks': {'back': {'ipv4_address': a['db']}},
               'healthcheck': {'test': ['CMD', 'pg_isready', '-U', 'postgres', '-d', 'postgres'],
                               'interval': '5s', 'timeout': '5s', 'retries': 30}},
        'redis': {**common, 'image': images['redis'], 'user': '999:999', 'mem_limit': '384m', 'cpus': 1,
                  'entrypoint': ['/bin/sh', '/opt/redis.sh'], 'secrets': ['redis_password'],
                  'tmpfs': ['/tmp:rw,noexec,nosuid,size=16m,uid=999,gid=999',
                            '/data:ro,noexec,nosuid,size=1m,mode=0555'],
                  'volumes': [mount('generated/redis.sh', '/opt/redis.sh', True)],
                  'networks': {'back': {'ipv4_address': a['redis']}},
                  'healthcheck': {'test': ['CMD-SHELL', 'REDISCLI_AUTH="$$(cat /run/secrets/redis_password)" redis-cli ping | grep -qx PONG'],
                                  'interval': '5s', 'timeout': '5s', 'retries': 20}},
    }, 'secrets': {n: {'file': state + '/secrets/' + n} for n in
                  ['admin_password', 'db_password', 'postgres_password', 'redis_password']},
        'networks': {name: {'name': 'nextcloud_' + name, 'driver': 'bridge', 'internal': name == 'back',
                           'enable_ipv6': False,
                           'driver_opts': {'com.docker.network.bridge.name': 'br-nc-' + name,
                                           'com.docker.network.bridge.enable_ip_masquerade': 'false'},
                           'ipam': {'config': [{'subnet': c[key]}]}}
                     for name, key in [('front', 'frontend_subnet'), ('back', 'backend_subnet')]}}


def render(c, state, images, app_image='nextcloud-unbuilt:blocked'):
    validate(c)
    state = Path(state).absolute()
    if not re.fullmatch(r'/[a-zA-Z0-9_./-]+', str(state)):
        raise ValueError('Путь состояния должен быть абсолютным и без спецсимволов')
    out = state / 'generated'
    out.mkdir(parents=True, exist_ok=True)
    files = {'security.config.php': php_config(c), 'nginx.conf': nginx_config(c),
             'nextcloud.nft': firewall(c),
             'compose.json': json.dumps(compose(c, state, images, app_image), indent=2) + '\n'}
    rules = filter_rules(c)
    files['filter-chains.nft'] = '\n'.join(
        f'chain nc_{name} {{\n    {body}\n    return\n}}\n' for name, body in rules.items())
    for name in rules:
        files[f'{name}-jump.nft'] = f'jump nc_{name} comment "nextcloud-stack"\n'
    for name, data in files.items():
        (out / name).write_text(data)
    return out
