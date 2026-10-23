#!/bin/bash
set -e

# Copy mounted files locally — old PHP versions (<7.4) have a bug reading
# bind-mounted files on Docker Desktop's VirtioFS layer.
if [ -f /mnt/canary/index.php ]; then
    cp /mnt/canary/index.php /var/www/canary/index.php
fi

# Start PHP-FPM in background
php-fpm --daemonize

# Start nginx in foreground (keeps container alive)
nginx
