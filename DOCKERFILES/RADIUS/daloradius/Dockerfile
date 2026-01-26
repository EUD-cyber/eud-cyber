FROM php:5.6-apache

# Fix Debian Stretch repositories (use archive.debian.org)
RUN sed -i 's|deb.debian.org|archive.debian.org|g' /etc/apt/sources.list && \
    sed -i 's|security.debian.org|archive.debian.org|g' /etc/apt/sources.list && \
    sed -i '/stretch-updates/d' /etc/apt/sources.list && \
    apt-get update -o Acquire::Check-Valid-Until=false && \
    apt-get install -y \
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
