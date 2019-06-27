#!/bin/bash
yum install epel-release -y
rpm -Uvh https://mirror.webtatic.com/yum/el7/webtatic-release.rpm
rpm -Uvh https://centos7.iuscommunity.org/ius-release.rpm
yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm
yum install deltarpm -y -q
yum install -y php70w* httpd24u httpd24u-tools httpd24u-devel policycoreutils-python ntpdate nfs-utils
ntpdate pool.ntp.org
systemctl enable ntpdate
systemctl start ntpdate
yum update -y
mkdir -p /mnt/efs
mount -t nfs4 -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,acl,fsc ${mount_point}:/ /mnt/efs
echo "${mount_point}:/ /mnt/efs nfs4 _netdev,auto,nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,acl,fsc 0 0" | sudo tee -a /etc/fstab
mkdir -p /etc/httpd/sites-available
mkdir -p /etc/httpd/sites-enabled

cat << EOF_VHOST > /etc/httpd/sites-available/${domain}.conf
<VirtualHost *:80>
        ServerAdmin devops@vogdigital.com
        DocumentRoot /mnt/efs/html
        DirectoryIndex index.php index.html
        SetEnv DB_ENDPOINT ${database}
        SetEnv REDIS_ENDPOINT ${redis}
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

cat << EOF_EXPIRES > /etc/httpd/conf.modules.d/02-expires.conf
<IfModule mod_expires.c>
ExpiresActive On" >> /etc/httpd/conf.modules.d/02-expires.conf
ExpiresByType image/jpg "access plus 1 year"
ExpiresByType image/jpeg "access plus 1 year"
ExpiresByType image/gif "access plus 1 year"
ExpiresByType image/png "access plus 1 year"
ExpiresByType text/css "access plus 1 month"
ExpiresByType application/pdf "access plus 1 month"
ExpiresByType text/x-javascript "access plus 1 month"
ExpiresByType application/javascript "access plus 1 month"
ExpiresByType application/x-shockwave-flash "access plus 1 month"
ExpiresByType image/x-icon "access plus 1 year"
ExpiresDefault "access plus 2 days"
</IfModule>
Header unset ETag
FileETag None
EOF_EXPIRES

cat << EOF_DEFLATE > /etc/httpd/conf.modules.d/03-deflate.conf
<IfModule mod_deflate.c>
SetOutputFilter DEFLATE
SetEnvIfNoCase Request_URI \.(?:gif|jpe?g|png)$ no-gzip dont-vary
SetEnvIfNoCase Request_URI \.(?:exe|t?gz|zip|bz2|sit|rar)$ no-gzip dont-vary
</IfModule>
<IfModule mod_headers.c>
Header append Vary User-Agent
</IfModule>
EOF_DEFLATE

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

echo "" > /etc/httpd/conf.d/php.conf

sed -i 's/LoadModule mpm_prefork_module/#LoadModule mpm_prefork_module/' /etc/httpd/conf.modules.d/00-mpm.conf
sed -i 's/#LoadModule mpm_event_module/LoadModule mpm_event_module/' /etc/httpd/conf.modules.d/00-mpm.conf

sudo cat <<EOF_POOL > /etc/php-fpm.d/${domain}.conf
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
cat << EOF_FPM > /etc/php-fpm.conf
include=/etc/php-fpm.d/*.conf
[global]
pid = /run/php-fpm/php-fpm.pid
error_log = syslog
syslog.facility = local1
syslog.ident = php-fpm
emergency_restart_threshold = 5
emergency_restart_interval = 1m
process_control_timeout = 5s
daemonize = no
EOF_FPM

if [ -d "/mnt/efs/html" ]; then
  sudo chown apache:apache /mnt/efs/html -R
fi

echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf
echo "fs.file-max = 4000000" >> /etc/sysctl.conf
echo "ulimit -n 65536" >> /etc/sysconfig/httpd


setsebool -P httpd_enable_cgi 1
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
sudo systemctl enable amazon-ssm-agent
sudo systemctl start amazon-ssm-agent
systemctl start httpd
systemctl enable httpd