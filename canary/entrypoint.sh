#!/bin/bash
set -e

# Start PHP-FPM in background
php-fpm --daemonize

# Start nginx in foreground (keeps container alive)
nginx
