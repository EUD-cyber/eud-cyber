FROM ubuntu:24.04

RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y \
    apache2 php php-mysql unzip curl mariadb-client ca-certificates && \
    curl -L https://github.com/lirantal/daloradius/archive/refs/heads/master.zip -o /tmp/daloradius.zip && \
    unzip /tmp/daloradius.zip -d /var/www && \
    mv /var/www/daloradius-* /var/www/html && \
    chown -R www-data:www-data /var/www/html && \
    rm -rf /tmp/daloradius.zip

EXPOSE 80
CMD ["apachectl","-D","FOREGROUND"]
