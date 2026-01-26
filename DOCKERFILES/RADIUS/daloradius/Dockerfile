FROM ubuntu:24.04

RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y \
    apache2 php php-mysql unzip curl mariadb-client ca-certificates && \
    rm -rf /var/www/html/* && \
    curl -L https://github.com/lirantal/daloradius/archive/refs/heads/master.zip -o /tmp/daloradius.zip && \
    unzip /tmp/daloradius.zip -d /tmp && \
    cp -r /tmp/daloradius-*/* /var/www/html/ && \
    chown -R www-data:www-data /var/www/html && \
    rm -rf /tmp/daloradius.zip /tmp/daloradius-*

EXPOSE 80
CMD ["apachectl","-D","FOREGROUND"]
