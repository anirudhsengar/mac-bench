FROM php:8.2-apache-bookworm@sha256:46804ea2b61eaf25ca47fa8aafc917015b8dad6b7a64c4364bb051a9dff275d5

WORKDIR /var/www/html

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      zlib1g-dev \
      libpng-dev \
      libjpeg-dev \
      libfreetype6-dev \
      iputils-ping \
      mariadb-client \
      ca-certificates \
      curl \
 && rm -rf /var/lib/apt/lists/* \
 && docker-php-ext-configure gd --with-jpeg --with-freetype \
 && docker-php-ext-install gd mysqli pdo pdo_mysql

# Copy or verify pinned DVWA release 2.3 archive (SHA-256 verified)
COPY dvwa-src.tar.gz /tmp/dvwa-2.3.tar.gz
RUN echo "f19bed738dd2d3867b5a7d50ffafe6fe07b30278824467e0ff24a1737e009f22  /tmp/dvwa-2.3.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/dvwa-2.3.tar.gz --strip-components=1 -C /var/www/html \
 && rm -f /tmp/dvwa-2.3.tar.gz

COPY config.inc.php /var/www/html/config/config.inc.php

RUN chown -R www-data:www-data /var/www/html \
 && { \
      echo "display_errors = Off"; \
      echo "log_errors = On"; \
      echo "allow_url_fopen = On"; \
      echo "allow_url_include = On"; \
    } > /usr/local/etc/php/conf.d/dvwa-bench.ini
