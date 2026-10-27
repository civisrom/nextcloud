"""Проверки прав хоста и фактической изоляции контейнеров, без вывода секретов."""
import json
from pathlib import Path
import stat
import subprocess


def no_symlinks(path):
    path = Path(path).absolute()
    if '..' in path.parts:
        raise ValueError('Путь с .. запрещён')
    for part in [*reversed(path.parents), path]:
        if part.is_symlink():
            raise ValueError('Символическая ссылка в служебном пути: ' + str(part))


def private_directory(path, create=False, owner=0):
    path = Path(path)
    no_symlinks(path)
    if owner == 0:
        for parent in path.parents:
            if parent.exists():
                s = parent.stat()
                # /tmp со sticky допустим для тестов; чужой вложенный каталог — нет.
                sticky_root = s.st_uid == 0 and bool(s.st_mode & stat.S_ISVTX)
                if s.st_uid != 0 or (s.st_mode & 0o022 and not sticky_root):
                    raise ValueError('Родитель служебного каталога доступен на запись посторонним: ' + str(parent))
    if create:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    facts = path.stat()
    if not stat.S_ISDIR(facts.st_mode) or facts.st_uid != owner or stat.S_IMODE(facts.st_mode) != 0o700:
        raise ValueError('Служебный каталог должен иметь нужного владельца и права 0700: ' + str(path))


def nft_structure(document):
    """Счётчики и kernel handles меняются, порядок правил и выражения — значимы."""
    def clean(value):
        if isinstance(value, list):
            return [clean(x) for x in value]
        if isinstance(value, dict):
            return {k: (None if k == 'counter' else clean(v)) for k, v in value.items()
                    if k not in {'handle', 'index'}}
        return value
    return clean([x for x in document['nftables'] if 'metainfo' not in x])


def check_firewall(config):
    # Компиляция эталона в отдельном netns не меняет ruleset хоста.
    command = 'nft -f /dev/stdin && nft -j list ruleset'
    expected = subprocess.run(['unshare', '--net', '--', 'sh', '-c', command],
                              input=config, text=True, capture_output=True, timeout=30)
    if expected.returncode:
        raise ValueError('Не удалось проверить эталон nftables в отдельном network namespace')
    reference = json.loads(expected.stdout)
    active = []
    for family, table in [('inet', 'nextcloud'), ('ip', 'nextcloud_nat'), ('bridge', 'nextcloud_l2')]:
        result = subprocess.run(['nft', '-j', 'list', 'table', family, table],
                                text=True, capture_output=True, timeout=30)
        if result.returncode:
            raise ValueError('Нет обязательной таблицы nftables: ' + table)
        active.extend(json.loads(result.stdout)['nftables'])
    if nft_structure(reference) != nft_structure({'nftables': active}):
        raise ValueError('Активные правила Nextcloud отличаются от эталона; запуск запрещён')


def check_container(name, facts, spec, definition, image_id):
    def require(ok, message):
        if not ok:
            raise ValueError('Нарушена изоляция ' + name + ': ' + message)
    host, config = facts['HostConfig'], facts['Config']
    require(facts['Image'] == image_id, 'образ')
    require(config.get('User') == spec['user'], 'UID/GID')
    require(not host.get('Privileged') and host.get('ReadonlyRootfs'), 'rootfs/privileged')
    require(not host.get('CapAdd') and host.get('CapDrop') == ['ALL'], 'capabilities')
    require(host.get('SecurityOpt') == ['no-new-privileges:true'], 'security_opt')
    require(not host.get('PortBindings') and not config.get('PublishAllPorts'), 'публичные порты')
    require(not host.get('PublishAllPorts'), 'publish-all')
    require(not host.get('Devices') and not host.get('DeviceRequests'), 'устройства')
    require(not host.get('VolumesFrom'), 'чужие volumes')
    require(host.get('PidMode') != 'host' and host.get('IpcMode') != 'host'
            and host.get('UTSMode') != 'host' and host.get('NetworkMode') != 'host', 'host namespaces')
    require(host.get('RestartPolicy', {}).get('Name') == 'no', 'порядок запуска/firewall')
    require(host.get('PidsLimit') == spec['pids_limit'], 'лимит PID')
    # Compose допускает суффиксы m/g; в спецификации проекта используются только они.
    memory = spec['mem_limit'].lower()
    expected_memory = int(memory[:-1]) * {'m': 1024**2, 'g': 1024**3}[memory[-1]]
    require(host.get('Memory') == expected_memory and host.get('NanoCpus') == int(spec['cpus'] * 10**9),
            'лимит RAM/CPU')
    require(host.get('Sysctls', {}).get('net.ipv6.conf.all.disable_ipv6') == '1', 'IPv6')
    mounts = {m['target']: (m['source'], not m['read_only']) for m in spec['volumes']}
    mounts.update({'/run/secrets/' + n: (definition['secrets'][n]['file'], False) for n in spec['secrets']})
    actual = {m['Destination']: m for m in facts['Mounts'] if m['Type'] != 'tmpfs'}
    require(set(actual) == set(mounts), 'набор подключённых каталогов/секретов')
    for target, (source, writable) in mounts.items():
        m = actual[target]
        require(m['Type'] == 'bind' and m['Source'] == source and m['RW'] == writable,
                'режим/источник mount ' + target)
    tmpfs = dict(x.split(':', 1) for x in spec['tmpfs'])
    require(host.get('Tmpfs') == tmpfs, 'tmpfs')
    networks = facts['NetworkSettings']['Networks']
    wanted = {definition['networks'][n]['name']: v['ipv4_address'] for n, v in spec['networks'].items()}
    require(set(networks) == set(wanted), 'набор сетей')
    for network, address in wanted.items():
        require(networks[network]['IPAddress'] == address, 'адрес сети ' + network)
    env = dict(x.split('=', 1) for x in config.get('Env', []) if '=' in x)
    if name == 'app':
        require(env.get('NEXTCLOUD_CONFIG_DIR') == '/var/lib/nextcloud/config'
                and env.get('NC_CONFIG_WRITABLE') != '1', 'неизменяемая конфигурация')
