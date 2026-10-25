# PHP CanaryWall — Canary Container (Multi-Version)
ARG PHP_IMAGE=php:8.4-fpm
FROM ${PHP_IMAGE}

# Fix archived Debian repos for EOL distros
COPY fix-apt.sh /tmp/fix-apt.sh
RUN chmod +x /tmp/fix-apt.sh && /tmp/fix-apt.sh && \
    apt-get install -y --no-install-recommends nginx curl procps && \
    rm -rf /var/lib/apt/lists/* /tmp/fix-apt.sh

# Enable the session extension (may already be compiled in)
RUN docker-php-ext-install session 2>/dev/null || true

# Create directories
RUN mkdir -p /var/www/canary /tmp/php-sessions /var/log/sentinel && \
    chown -R www-data:www-data /tmp/php-sessions /var/www/canary

# Copy canary PHP script
COPY index.php /var/www/canary/index.php

# Copy PHP configuration
COPY php.ini /usr/local/etc/php/conf.d/sentinel-canary.ini

# Copy FPM pool configuration — nuke ALL default pools first
RUN rm -f /usr/local/etc/php-fpm.d/*.conf
COPY fpm.conf /usr/local/etc/php-fpm.d/canary.conf

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Startup script — run both FPM and nginx
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 9080

# Override the base image's entrypoint so our script runs directly
ENTRYPOINT []
CMD ["/entrypoint.sh"]
