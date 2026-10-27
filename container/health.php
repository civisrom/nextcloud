<?php
declare(strict_types=1);
$context = stream_context_create(['http' => [
    'timeout' => 5,
    'header' => 'Host: ' . getenv('NC_DOMAIN') . "\r\n",
]]);
$result = @file_get_contents('http://127.0.0.1:8080/status.php', false, $context);
$status = $result === false ? null : json_decode($result, true);
exit(is_array($status) && ($status['installed'] ?? false)
    && !($status['maintenance'] ?? true) && !($status['needsDbUpgrade'] ?? true) ? 0 : 1);
