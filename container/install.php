<?php
// Секреты не передаются через argv / docker inspect / журнал команд.
declare(strict_types=1);
chdir('/srv/nextcloud');
if (is_file('/var/lib/nextcloud/config/config.php')) {
    fwrite(STDERR, "Конфигурация уже существует; используйте upgrade или восстановление.\n");
    exit(1);
}
$argv = [
    'occ', 'maintenance:install', '--no-interaction',
    '--database=pgsql', '--database-host=db', '--database-name=nextcloud',
    '--database-user=nextcloud',
    '--database-pass=' . trim(file_get_contents('/run/secrets/db_password')),
    '--admin-user=' . getenv('NC_ADMIN_USER'),
    '--admin-pass=' . trim(file_get_contents('/run/secrets/admin_password')),
    '--data-dir=/var/lib/nextcloud/data',
];
$_SERVER['argv'] = $argv;
$_SERVER['argc'] = count($argv);
require '/srv/nextcloud/console.php';
