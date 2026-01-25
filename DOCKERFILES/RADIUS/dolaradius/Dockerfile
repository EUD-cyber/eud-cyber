FROM ubuntu:22.04

RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y \
    apache2 php php-mysql git unzip mariadb-client && \
    git clone https://github.com/lirantal/daloradius.git /var/www/html && \
    chown -R www-data:www-data /var/www/html

EXPOSE 80
CMD ["apachectl","-D","FOREGROUND"]
