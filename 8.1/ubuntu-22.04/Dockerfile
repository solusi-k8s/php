FROM ubuntu:22.04


LABEL Component="php" \
      Name="solusik8s/php" \
      Version="8.1-ubuntu-20.04" \
      Release="1"
ENV TZ 'Asia/Jakarta'
ENV DEBIAN_FRONTEND noninteractive
RUN set -ex; \
	\
    echo $TZ > /etc/timezone && \
    apt-get update && apt-get install -y tzdata && \
    rm -vf /etc/localtime && \
    ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && \
    dpkg-reconfigure -f noninteractive tzdata

RUN apt -y update
RUN apt install -y php php
RUN apt install -y php-pgsql php-gd php-mysql php-pear php-xml php-redis
RUN apt install -y php-curl
RUN apt install -y php-zip
RUN apt install -y apache2
RUN a2enmod ssl
RUN apt install -y ca-certificates curl
RUN	apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false; \
	rm -rf /var/lib/apt/lists/*

EXPOSE 80

COPY ./root /

RUN chmod 755 /usr/bin/apache2-foreground

CMD ["apache2-foreground"]

