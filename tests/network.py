#!/usr/bin/env python3
"""Реальные пакеты nftables в отдельном network+mount namespace; нужен root."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from configuration import firewall


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--firewall', type=Path, help='Необязательно: полный локальный конфиг с include')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Нужен root для unshare/netns')
    if not args.inside:
        # Родительский netns сохраняется в env, чтобы исключить ошибочный запуск --inside на хосте.
        env = dict(os.environ, NC_TEST_PARENT_NETNS=os.readlink('/proc/self/ns/net'))
        command = ['unshare', '--net', '--mount', '--propagation', 'private', '--fork',
                   sys.executable, str(Path(__file__).resolve()), '--inside']
        if args.firewall:
            command.extend(['--firewall', str(args.firewall.absolute())])
        raise SystemExit(subprocess.call(command, env=env))
    if not os.environ.get('NC_TEST_PARENT_NETNS') or os.readlink('/proc/self/ns/net') == os.environ['NC_TEST_PARENT_NETNS']:
        raise SystemExit('Запрещено выполнять тесты в network namespace хоста')
    Path('/run/netns').mkdir(exist_ok=True)
    run('mount', '-t', 'tmpfs', 'tmpfs', '/run/netns')
    run('ip', 'link', 'set', 'lo', 'up')
    Path('/proc/sys/net/ipv4/ip_forward').write_text('1')
    processes = []
    namespaces = ['nc-test-app', 'nc-test-db', 'nc-test-redis', 'nc-test-wan']
    for name in namespaces:
        run('ip', 'netns', 'add', name)
        run('ip', '-n', name, 'link', 'set', 'lo', 'up')
    for name, ip in [('br-nc-front', '172.30.90.1/28'), ('br-nc-back', '172.30.91.1/28')]:
        run('ip', 'link', 'add', name, 'type', 'bridge')
        run('ip', 'address', 'add', ip, 'dev', name)
        run('ip', 'link', 'set', name, 'up')
    def endpoint(ns, dev, peer, ip, bridge=None):
        run('ip', 'link', 'add', dev, 'type', 'veth', 'peer', 'name', peer)
        run('ip', 'link', 'set', peer, 'netns', ns)
        if bridge:
            run('ip', 'link', 'set', dev, 'master', bridge)
        run('ip', 'link', 'set', dev, 'up')
        run('ip', '-n', ns, 'address', 'add', ip, 'dev', peer)
        run('ip', '-n', ns, 'link', 'set', peer, 'up')
    endpoint('nc-test-app', 'app-front', 'eth0', '172.30.90.2/28', 'br-nc-front')
    endpoint('nc-test-app', 'app-back', 'eth1', '172.30.91.2/28', 'br-nc-back')
    endpoint('nc-test-db', 'db-back', 'eth0', '172.30.91.3/28', 'br-nc-back')
    endpoint('nc-test-redis', 'redis-back', 'eth0', '172.30.91.4/28', 'br-nc-back')
    endpoint('nc-test-wan', 'net0', 'eth0', '8.8.4.2/24')
    run('ip', 'address', 'add', '8.8.4.1/24', 'dev', 'net0')
    run('ip', 'route', 'add', 'default', 'via', '8.8.4.2')
    run('ip', '-n', 'nc-test-app', 'route', 'add', 'default', 'via', '172.30.90.1')
    run('ip', '-n', 'nc-test-wan', 'route', 'add', 'default', 'via', '8.8.4.1')
    for ip in ['1.1.1.1/32', '169.254.169.254/32', '10.15.0.2/32']:
        run('ip', '-n', 'nc-test-wan', 'address', 'add', ip, 'dev', 'lo')
    serve = '''import socket,select,sys
listeners=[]
for address in sys.argv[1].split(','):
 for port in map(int,sys.argv[2:]):
  for kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
   s=socket.socket(socket.AF_INET,kind);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((address,port))
   if kind==socket.SOCK_STREAM:s.listen(8)
   listeners.append(s)
print('ready',flush=True)
while True:
 for s in select.select(listeners,[],[])[0]:
  if s.type==socket.SOCK_DGRAM:
   data,peer=s.recvfrom(1024);s.sendto(data,peer)
  else:
   c,_=s.accept();c.close()
'''
    def server(ns, *ports):
        prefix = ['ip', 'netns', 'exec', ns] if ns else []
        bind = '8.8.4.2,1.1.1.1,169.254.169.254,10.15.0.2' if ns == 'nc-test-wan' else '0.0.0.0'
        p = subprocess.Popen(prefix + ['python3', '-u', '-c', serve, bind, *map(str, ports)], stdout=subprocess.PIPE, text=True)
        processes.append(p)
        if p.stdout.readline().strip() != 'ready':
            raise RuntimeError('Тестовый listener не запустился')
    connect = '''import socket,sys
udp=sys.argv[3]=='udp'
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM);s.settimeout(0.7)
try:
 s.connect((sys.argv[1],int(sys.argv[2])))
 if udp:s.send(b'probe');s.recv(1024)
 sys.exit(0)
except OSError: sys.exit(1)
'''
    def check(ns, ip, port, expected, title, protocol='tcp'):
        prefix = ['ip', 'netns', 'exec', ns] if ns else []
        rc = subprocess.call(prefix + ['python3', '-c', connect, ip, str(port), protocol])
        if (rc == 0) != expected:
            raise AssertionError(title)
        print('PASS ' + title, flush=True)
    try:
        server(None, 22, 443)
        server('nc-test-app', 8080)
        server('nc-test-db', 5432, 8080)
        server('nc-test-redis', 6379, 8080)
        server('nc-test-wan', 53, 80, 443, 853)
        # До firewall проверяем, что отрицательные проверки действительно имеют listener.
        check('nc-test-app', '172.30.91.3', 8080, True, 'listener до фильтрации')
        with tempfile.TemporaryDirectory() as tmp:
            config = args.firewall or Path(tmp) / 'nextcloud.nft'
            if not args.firewall:
                config.write_text(firewall(json.loads((ROOT / 'site.example.json').read_text())))
            run('nft', '--check', '--file', str(config))
            run('nft', '--file', str(config))
        check(None, '172.30.90.2', 8080, True, 'хост → Nextcloud')
        check(None, '172.30.91.3', 5432, False, 'хост → PostgreSQL запрещено')
        check('nc-test-app', '172.30.91.3', 5432, True, 'Nextcloud → PostgreSQL')
        check('nc-test-app', '172.30.91.4', 6379, True, 'Nextcloud → Redis')
        check('nc-test-app', '172.30.91.3', 8080, False, 'лишний порт backend запрещён')
        check('nc-test-db', '172.30.91.4', 6379, False, 'БД → Redis запрещено')
        check('nc-test-app', '172.30.90.1', 443, True, 'self-check → HTTPS хоста')
        check('nc-test-app', '8.8.4.1', 443, False, 'другие HTTPS-vhost хоста запрещены')
        check('nc-test-app', '172.30.90.1', 22, False, 'доступ к SSH хоста запрещён')
        check('nc-test-app', '1.1.1.1', 443, True, 'исходящий HTTPS и NAT')
        check('nc-test-app', '1.1.1.1', 53, True, 'разрешённый DNS TCP')
        check('nc-test-app', '1.1.1.1', 53, True, 'разрешённый DNS UDP', 'udp')
        check('nc-test-app', '1.1.1.1', 443, False, 'исходящий QUIC запрещён', 'udp')
        check('nc-test-app', '172.30.91.4', 6379, False, 'Redis UDP запрещён', 'udp')
        check('nc-test-app', '1.1.1.1', 80, False, 'исходящий HTTP запрещён')
        check('nc-test-app', '8.8.4.2', 53, False, 'посторонний DNS запрещён')
        check('nc-test-app', '169.254.169.254', 443, False, 'metadata endpoint запрещён')
        check('nc-test-app', '10.15.0.2', 443, False, 'доступ в приватную сеть запрещён')
        check('nc-test-wan', '172.30.90.2', 8080, False, 'WAN → Nextcloud напрямую запрещено')
        check('nc-test-wan', '172.30.91.3', 5432, False, 'WAN → PostgreSQL запрещено')
    finally:
        for p in processes:
            p.terminate()
            p.wait(timeout=5)
        for name in namespaces:
            run('ip', 'netns', 'delete', name)


if __name__ == '__main__':
    main()
