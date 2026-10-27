ARG NEXTCLOUD_IMAGE
FROM ${NEXTCLOUD_IMAGE}

# Исходный образ проверяется ДО сборки; сборка работает без сети.
USER root
RUN mkdir -p /srv/nextcloud /var/lib/nextcloud/config /var/lib/nextcloud/apps /var/lib/nextcloud/data \
    && cp -a /usr/src/nextcloud/. /srv/nextcloud/ \
    && rm -rf /srv/nextcloud/config /srv/nextcloud/custom_apps /srv/nextcloud/data \
    && ln -s /var/lib/nextcloud/config /srv/nextcloud/config \
    && ln -s /var/lib/nextcloud/apps /srv/nextcloud/custom_apps \
    && ln -s /var/lib/nextcloud/data /srv/nextcloud/data \
    && printf 'Listen 8080\n' > /etc/apache2/ports.conf \
    && a2disconf remoteip \
    && chown -R 33:33 /var/lib/nextcloud
COPY container/apache.conf /etc/apache2/sites-available/000-default.conf
COPY container/php.ini /usr/local/etc/php/conf.d/zz-security.ini
COPY container/install.php /opt/nextcloud/install.php
COPY container/health.php /opt/nextcloud/health.php
WORKDIR /srv/nextcloud
ENV APACHE_RUN_USER=www-data APACHE_RUN_GROUP=www-data
USER 33:33
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD ["php", "/opt/nextcloud/health.php"]
ENTRYPOINT ["apache2-foreground"]
