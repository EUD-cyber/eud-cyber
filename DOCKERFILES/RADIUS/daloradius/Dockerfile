FROM ubuntu:24.04

RUN apt update && DEBIAN_FRONTEND=noninteractive apt install -y \
    apache2 php php-mysql php-gd php-xml php-curl php-mbstring \
    php-pear php-db unzip curl mariadb-client ca-certificates && \
    rm -rf /var/www/html/* && \
    curl -L https://github.com/lirantal/daloradius/archive/refs/heads/master.zip -o /tmp/daloradius.zip && \
    unzip /tmp/daloradius.zip -d /tmp && \
    cp -r /tmp/daloradius-*/* /var/www/html/ && \
    chown -R www-data:www-data /var/www/html && \
    rm -rf /tmp/daloradius.zip /tmp/daloradius-* && \
    sed -i 's|DocumentRoot /var/www/html|DocumentRoot /var/www/html/app/operators|g' /etc/apache2/sites-enabled/000-default.conf && \
    echo "ServerName localhost" >> /etc/apache2/apache2.conf

EXPOSE 80
CMD ["apachectl","-D","FOREGROUND"]
