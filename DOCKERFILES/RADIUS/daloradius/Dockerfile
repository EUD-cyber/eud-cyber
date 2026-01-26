FROM php:5.6-apache

RUN apt-get update && apt-get install -y \
    mariadb-client \
    unzip \
    curl \
    ca-certificates \
    php-pear && \
    pear install DB

# Download daloRADIUS
RUN rm -rf /var/www/html/* && \
    curl -L https://github.com/lirantal/daloradius/archive/refs/heads/master.zip -o /tmp/daloradius.zip && \
    unzip /tmp/daloradius.zip -d /tmp && \
    cp -r /tmp/daloradius-*/* /var/www/html/ && \
    rm -rf /tmp/daloradius.zip /tmp/daloradius-*

# Fix Apache webroot
RUN sed -i 's|DocumentRoot /var/www/html|DocumentRoot /var/www/html/app/operators|g' /etc/apache2/sites-enabled/000-default.conf && \
    echo "ServerName localhost" >> /etc/apache2/apache2.conf

COPY init.sh /init.sh
RUN chmod +x /init.sh

EXPOSE 80
CMD ["/init.sh"]
