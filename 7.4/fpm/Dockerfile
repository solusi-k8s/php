FROM php:7.4.32-fpm

ENV TZ 'Asia/Jakarta'
RUN set -ex; \
	\
    echo $TZ > /etc/timezone && \
    apt-get update && apt-get install -y tzdata && \
    rm -vf /etc/localtime && \
    ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata; \
    date; \
	savedAptMark="$(apt-mark showmanual)"; \
	\
	apt-get update; \
	apt-get install -y --no-install-recommends \
        libfreetype6-dev \
        libjpeg62-turbo-dev \
        libmcrypt-dev \
        libpng-dev \
        libicu-dev \
        libpq-dev \
        libxpm-dev \
        libvpx-dev \
        libmcrypt-dev \
        libzip-dev \
    && pecl install xdebug \
    && docker-php-ext-enable xdebug \
    && pecl install redis \
    && docker-php-ext-enable redis \
    && pecl install mcrypt && docker-php-ext-enable mcrypt \
    && docker-php-ext-install -j$(nproc) zip \
    && docker-php-ext-install -j$(nproc) pgsql \
    && docker-php-ext-install -j$(nproc) pdo_pgsql \
    && docker-php-ext-install -j$(nproc) intl \
    && docker-php-ext-install -j$(nproc) exif \
    && docker-php-ext-configure gd --with-jpeg --with-xpm --with-freetype \
    && docker-php-ext-install -j$(nproc) gd; \
	\
    # reset apt-mark's "manual" list so that "purge --auto-remove" will remove all build dependencies
	apt-mark auto '.*' > /dev/null; \
	apt-mark manual $savedAptMark; \
	ldd "$(php -r 'echo ini_get("extension_dir");')"/*.so \
		| awk '/=>/ { print $3 }' \
		| sort -u \
		| xargs -r dpkg-query -S \
		| cut -d: -f1 \
		| sort -u \
		| xargs -rt apt-mark manual; \
	\
	apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false; \
	rm -rf /var/lib/apt/lists/*

LABEL Component="php" \
      Name="solusik8s/php" \
      Version="7.4.32-fpm" \
      Release="1"
RUN addgroup --gid 9999 solusik8s
RUN adduser --disabled-password --gecos 'solusik8s,,,,' --uid 9999 --gid 9999 --home /home/solusik8s --shell /bin/bash solusik8s

RUN addgroup --gid 1000 user1000
RUN adduser --disabled-password --gecos 'user1000,,,,' --uid 1000 --gid 1000 --home /home/user1000 --shell /bin/bash user1000

RUN addgroup --gid 1001 user1001
RUN adduser --disabled-password --gecos 'user1001,,,,' --uid 1001 --gid 1001 --home /home/user1001 --shell /bin/bash user1001
