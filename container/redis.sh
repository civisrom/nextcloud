#!/bin/sh
set -eu
# Пароль попадает только в tmpfs-файл, не в командную строку Redis.
umask 077
{
    printf 'bind 0.0.0.0\nport 6379\nprotected-mode yes\n'
    printf 'save ""\nappendonly no\nmaxmemory 256mb\nmaxmemory-policy noeviction\n'
    printf 'requirepass %s\n' "$(cat /run/secrets/redis_password)"
} > /tmp/redis.conf
exec redis-server /tmp/redis.conf
