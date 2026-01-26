#!/bin/bash

echo "Waiting for database..."
until mysql -h radius-db -u radius -pradius -e "SELECT 1" >/dev/null 2>&1; do
  sleep 5
done

echo "Creating daloRADIUS config..."
CONFIG_FILE=/var/www/html/app/common/includes/daloradius.conf.php

cat > $CONFIG_FILE <<EOF
<?php
\$configValues['FREERADIUS_VERSION'] = '3';
\$configValues['CONFIG_DB_ENGINE'] = 'mysql';
\$configValues['CONFIG_DB_HOST'] = 'radius-db';
\$configValues['CONFIG_DB_PORT'] = '3306';
\$configValues['CONFIG_DB_USER'] = 'radius';
\$configValues['CONFIG_DB_PASS'] = 'radius';
\$configValues['CONFIG_DB_NAME'] = 'radius';
?>
EOF

chown www-data:www-data $CONFIG_FILE

echo "Importing database schema..."
mysql -h radius-db -u radius -pradius radius < /var/www/html/contrib/db/mysql-daloradius.sql
mysql -h radius-db -u radius -pradius radius < /var/www/html/contrib/db/fr2-mysql-daloradius-and-freeradius.sql

echo "Starting Apache..."
exec apachectl -D FOREGROUND
