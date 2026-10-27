#!/usr/bin/env python3
"""Получить digest актуальных официальных образов в выбранных major-ветках."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import urllib.request


def get(url, headers=None):
    request = urllib.request.Request(url, headers={'User-Agent': 'civisrom-nextcloud-lock', **(headers or {})})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read(), response.headers


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true', help='Заменить images.lock.json после получения всех digest')
    args = parser.parse_args()
    releases = json.loads(get('https://raw.githubusercontent.com/nextcloud/docker/master/versions.json')[0])
    version = releases['35']['version']
    if not re.fullmatch(r'35\.\d+\.\d+', version):
        raise ValueError('Неизвестный maintenance-релиз Nextcloud 35')
    tags = {'nextcloud': version + '-apache', 'postgres': '17-trixie', 'redis': '8.2-alpine'}
    images = {}
    for name, tag in tags.items():
        # Краткоживущий anonymous registry token используется только в памяти.
        token = json.loads(get('https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/' + name + ':pull')[0])['token']
        body, headers = get(f'https://registry-1.docker.io/v2/library/{name}/manifests/{tag}', {
            'Authorization': 'Bearer ' + token,
            'Accept': 'application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json',
        })
        digest = 'sha256:' + hashlib.sha256(body).hexdigest()
        if headers.get('Docker-Content-Digest') != digest:
            raise ValueError('Manifest digest не совпал с телом ответа реестра')
        images[name] = f'docker.io/library/{name}:{tag}@{digest}'
    output = json.dumps(images, indent=2) + '\n'
    if args.write:
        path = Path(__file__).resolve().parents[1] / 'images.lock.json'
        temporary = path.with_suffix('.json.new')
        temporary.write_text(output)
        temporary.replace(path)
        print('Lock обновлён. Сборка по-прежнему требует успешного сканирования.')
    else:
        print(output, end='')


if __name__ == '__main__':
    main()
