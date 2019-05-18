#!/bin/bash
yum install epel-release -y
rpm -Uvh https://mirror.webtatic.com/yum/el7/webtatic-release.rpm
rpm -Uvh https://centos7.iuscommunity.org/ius-release.rpm
yum install deltarpm -y -q
yum install -y php70w* httpd24u openssl httpd24u-tools httpd24u-devel mod24u_ssl policycoreutils-python ntpdate nfs-utils
ntpdate pool.ntp.org
systemctl enable ntpdate
systemctl start ntpdate
yum update -y
mkdir -p /mnt/efs
mount -t nfs4 -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport ${mount_point}:/ /mnt/efs
echo "${mount_point}:/ /mnt/efs nfs4 nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,nofail 0 0" | sudo tee -a /etc/fstab
mkdir -p /etc/httpd/sites-available
mkdir -p /etc/httpd/sites-enabled

cat << EOF_VHOST > /etc/httpd/sites-available/${domain}.conf
<VirtualHost *:80>
        ServerAdmin devops@vogdigital.com
        DocumentRoot /mnt/efs/html
        DirectoryIndex index.php index.html
        ServerName ${domain}
        ServerAlias www.${domain}
        <FilesMatch \.php$>
                SetHandler "proxy:unix:/var/run/${domain}.sock|fcgi://${domain}/"
        </FilesMatch>
        <Proxy fcgi://${domain}>
                ProxySet connectiontimeout=5 timeout=240
        </Proxy>
</VirtualHost>
EOF_VHOST

ln -s /etc/httpd/sites-available/${domain}.conf /etc/httpd/sites-enabled/${domain}.conf

cat <<EOF_HTTPD > /etc/httpd/conf/httpd.conf

ServerRoot "/etc/httpd"

Listen 80

Include conf.modules.d/*.conf

User apache
Group apache


ServerAdmin root@localhost

ServerName 127.0.0.1:80

<Directory />
    AllowOverride none
    Require all denied
</Directory>


DocumentRoot "/var/www/html"

<Directory "/var/www">
    AllowOverride None
    # Allow open access:
    Require all granted
</Directory>

<Directory "/var/www/html">
Options Indexes FollowSymLinks
AllowOverride All
Require all granted
</Directory>

<Directory "/mnt/efs">
Options Indexes FollowSymLinks
AllowOverride All
Require all granted
</Directory>

<IfModule dir_module>
    DirectoryIndex index.html index.php
</IfModule>

<Files ".ht*">
    Require all denied
</Files>

ErrorLog "logs/error_log"

LogLevel warn

<IfModule log_config_module>
    LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
    LogFormat "%h %l %u %t \"%r\" %>s %b" common

    <IfModule logio_module>
      LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\" %I %O" combinedio
    </IfModule>

    CustomLog "logs/access_log" combined
</IfModule>

<IfModule alias_module>
    ScriptAlias /cgi-bin/ "/var/www/cgi-bin/"
</IfModule>

<Directory "/var/www/cgi-bin">
    AllowOverride None
    Options None
    Require all granted
</Directory>

<IfModule mime_module>
    TypesConfig /etc/mime.types
    AddType application/x-compress .Z
    AddType application/x-gzip .gz .tgz
    AddType text/html .shtml
    AddOutputFilter INCLUDES .shtml
</IfModule>

AddDefaultCharset UTF-8

<IfModule mime_magic_module>
    MIMEMagicFile conf/magic
</IfModule>


EnableSendfile on

IncludeOptional conf.d/*.conf

<Location /server-status>
    RewriteEngine Off
    SetHandler server-status
    Require ip 10.0.0.0/8
    Require ip 127.0.0.1/32
</Location>
ErrorDocument 403 "403 Forbidden"
ErrorDocument 401 "401 Unauthorized"
ExtendedStatus on
ServerSignature Off
ServerTokens Prod
TraceEnable Off

<Directory "/var/www/html/*/site/wp-content/uploads/">
SetHandler none
SetHandler default-handler
Options -ExecCGI
RemoveHandler .cgi .php .php3 .php4 .php5 .phtml .pl .py .pyc .pyo
</Directory>
<Location "/wp-content/uploads/">
SetHandler none
SetHandler default-handler
Options -ExecCGI
RemoveHandler .cgi .php .php3 .php4 .php5 .phtml .pl .py .pyc .pyo
</Location>
LogFormat "%v %h %l %u %t \"%r\" %>s %b" vhost
CustomLog /var/log/httpd/multiple_vhost_log vhost

IncludeOptional sites-enabled/*.conf
EOF_HTTPD

echo "<IfModule mod_expires.c>" > /etc/httpd/conf.modules.d/02-expires.conf
echo "ExpiresActive On" >> /etc/httpd/conf.modules.d/02-expires.conf
echo 'ExpiresByType image/jpg "access plus 1 year"' >> /etc/httpd/conf.modules.d/02-expires.conf
echo 'ExpiresByType image/jpeg "access plus 1 year"' >> /etc/httpd/conf.modules.d/02-expires.conf
echo 'ExpiresByType image/gif "access plus 1 year"' >> /etc/httpd/conf.modules.d/02-expires.conf
echo 'ExpiresByType image/png "access plus 1 year"' >> /etc/httpd/conf.modules.d/02-expires.conf
echo 'ExpiresByType text/css "access plus 1 month"' >> /etc/httpd/conf.modules.d/02-expires.conf
echo 'ExpiresByType application/pdf "access plus 1 month"' >> /etc/httpd/conf.modules.d/02-expires.conf
echo 'ExpiresByType text/x-javascript "access plus 1 month"' >> /etc/httpd/conf.modules.d/02-expires.conf
echo 'ExpiresByType application/javascript "access plus 1 month"' >> /etc/httpd/conf.modules.d/02-expires.conf
echo 'ExpiresByType application/x-shockwave-flash "access plus 1 month"' >> /etc/httpd/conf.modules.d/02-expires.conf
echo 'ExpiresByType image/x-icon "access plus 1 year"' >> /etc/httpd/conf.modules.d/02-expires.conf
echo 'ExpiresDefault "access plus 2 days"' >> /etc/httpd/conf.modules.d/02-expires.conf
echo "</IfModule>" >> /etc/httpd/conf.modules.d/02-expires.conf
echo "Header unset ETag" >> /etc/httpd/conf.modules.d/02-expires.conf
echo "FileETag None" >> /etc/httpd/conf.modules.d/02-expires.conf
echo "<IfModule mod_deflate.c>" > /etc/httpd/conf.modules.d/03-deflate.conf
echo "SetOutputFilter DEFLATE" >> /etc/httpd/conf.modules.d/03-deflate.conf
echo "SetEnvIfNoCase Request_URI \.(?:gif|jpe?g|png)$ no-gzip dont-vary" >> /etc/httpd/conf.modules.d/03-deflate.conf
echo "SetEnvIfNoCase Request_URI \.(?:exe|t?gz|zip|bz2|sit|rar)$ no-gzip dont-vary" >> /etc/httpd/conf.modules.d/03-deflate.conf
echo "</IfModule>" >> /etc/httpd/conf.modules.d/03-deflate.conf
echo "<IfModule mod_headers.c>" >> /etc/httpd/conf.modules.d/03-deflate.conf
echo "Header append Vary User-Agent" >> /etc/httpd/conf.modules.d/03-deflate.conf
echo "</IfModule>" >> /etc/httpd/conf.modules.d/03-deflate.conf

cat << EOF_SSL > /etc/httpd/conf.d/ssl.conf
Listen 443 https
SSLPassPhraseDialog exec:/usr/libexec/httpd-ssl-pass-dialog
SSLSessionCache         shmcb:/run/httpd/sslcache(512000)
SSLSessionCacheTimeout  300
SSLRandomSeed startup file:/dev/urandom  256
SSLRandomSeed connect builtin
SSLCryptoDevice builtin
SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
SSLProtocol All -SSLv2 -SSLv3
SSLHonorCipherOrder On
#Header always set Strict-Transport-Security "max-age=63072000; includeSubdomains; preload"
#Header always set X-Frame-Options DENY
Header always set X-Content-Type-Options nosniff
SSLCompression off 
SSLSessionTickets Off
SSLUseStapling on 
SSLStaplingCache "shmcb:logs/stapling-cache(150000)" 
SSLStaplingResponderTimeout 30
<VirtualHost _default_:443>
ErrorLog logs/ssl_error_log
TransferLog logs/ssl_access_log
LogLevel warn
SSLEngine on
SSLProtocol all -SSLv2
SSLCipherSuite HIGH:MEDIUM:!aNULL:!MD5
SSLCertificateFile /etc/pki/tls/certs/localhost.crt
SSLCertificateKeyFile /etc/pki/tls/private/localhost.key
<Files ~ "\.(cgi|shtml|phtml|php3?)$">
    SSLOptions +StdEnvVars
</Files>
<Directory "/var/www/cgi-bin">
    SSLOptions +StdEnvVars
</Directory>
BrowserMatch "MSIE [2-5]" \
         nokeepalive ssl-unclean-shutdown \
         downgrade-1.0 force-response-1.0

CustomLog logs/ssl_request_log \
          "%t %h %{SSL_PROTOCOL}x %{SSL_CIPHER}x \"%r\" %b"
</VirtualHost>

EOF_SSL
echo "" > /etc/httpd/conf.d/welcome.conf
cat << EOF_AUTOINDEX > /etc/httpd/conf.d/autoindex.conf
IndexOptions FancyIndexing HTMLTable VersionSort
AddIconByEncoding (CMP,/icons/compressed.gif) x-compress x-gzip

AddIconByType (TXT,/icons/text.gif) text/*
AddIconByType (IMG,/icons/image2.gif) image/*
AddIconByType (SND,/icons/sound2.gif) audio/*
AddIconByType (VID,/icons/movie.gif) video/*

AddIcon /icons/binary.gif .bin .exe
AddIcon /icons/binhex.gif .hqx
AddIcon /icons/tar.gif .tar
AddIcon /icons/world2.gif .wrl .wrl.gz .vrml .vrm .iv
AddIcon /icons/compressed.gif .Z .z .tgz .gz .zip
AddIcon /icons/a.gif .ps .ai .eps
AddIcon /icons/layout.gif .html .shtml .htm .pdf
AddIcon /icons/text.gif .txt
AddIcon /icons/c.gif .c
AddIcon /icons/p.gif .pl .py
AddIcon /icons/f.gif .for
AddIcon /icons/dvi.gif .dvi
AddIcon /icons/uuencoded.gif .uu
AddIcon /icons/script.gif .conf .sh .shar .csh .ksh .tcl
AddIcon /icons/tex.gif .tex
AddIcon /icons/bomb.gif core.

AddIcon /icons/back.gif ..
AddIcon /icons/hand.right.gif README
AddIcon /icons/folder.gif ^^DIRECTORY^^
AddIcon /icons/blank.gif ^^BLANKICON^^

DefaultIcon /icons/unknown.gif
ReadmeName README.html
HeaderName HEADER.html
IndexIgnore .??* *~ *# HEADER* README* RCS CVS *,v *,t
EOF_AUTOINDEX

sudo cat <<EOF_POOL > /etc/php/7.0/fpm/pool.d/${domain}.conf
[${domain}]
listen = /var/run/${domain}.sock
listen.allowed_clients = 127.0.0.1
listen.owner = apache
listen.mode = 660
listen.group = apache
user = apache
group = apache

pm = ondemand
pm.max_children = 5
pm.max_requests = 200
pm.process_idle_timeout=10s

php_admin_value[open_basedir] = /var/www/html/${domain}:/usr/share/php:/tmp:/usr/share/phpmyadmin:/etc/phpmyadmin:/var/lib/phpmyadmin
php_admin_value[session.save_path] = /var/www/html/${domain}/tmp
php_admin_value[upload_tmp_dir] = /var/www/html/${domain}/tmp
EOF_POOL

if [ -d "/mnt/efs/html" ]; then
  sudo chown apache:apache /mnt/efs/html -R
fi

setsebool -P httpd_can_network_connect 1
setsebool -P httpd_can_network_connect_db 1
setsebool -P httpd_unified 1
setsebool -P httpd_setrlimit 1
setsebool -P httpd_execmem 1
setsebool -P httpd_can_sendmail 1
setsebool -P httpd_use_nfs 1
setsebool -P httpd_can_network_connect 1
setsebool -P httpd_graceful_shutdown 1

sudo systemctl start php-fpm
sudo systemctl enable php-fpm
sudo systemctl enable amazon-ssm-agent.service
sudo systemctl start amazon-ssm-agent.service
systemctl start httpd
systemctl enable httpd