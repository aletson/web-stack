#!/bin/bash
add-apt-repository ppa:ondrej/php
apt-get update && apt-get upgrade -y
apt-get install -y php7.0 php7.0-cli php7.0-common php7.0-curl php7.0-fpm php7.0-gd php7.0-json php7.0-mbstring php7.0-mcrypt php7.0-mysql php7.0-opcache php7.0-readline php7.0-soap php7.0-xml php7.0-zip nginx nfs-common
mkdir -p /mnt/efs
mount -t nfs4 -o nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport ${mount_point}:/ /mnt/efs
echo "${mount_point}:/ /mnt/efs nfs4 nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,nofail 0 0" | sudo tee -a /etc/fstab
mkdir -p /etc/nginx/sites-available
mkdir -p /etc/nginx/sites-enabled

cat << "EOF_VHOST" > /etc/nginx/sites-available/${domain}.conf
server {
  listen 80;
  server_name ${domain} www.${domain};
  root /mnt/efs/html;
  
  index index.php;
  location / {
    try_files $uri $uri/ /index.php?$args;
  }
  location ~* \.php$ {
    try_files $uri =404;
    fastcgi_pass unix:/var/run/${domain}.sock;
    include fastcgi_params;
    fastcgi_split_path_info ^(.+\.php)(/.+)$;
    fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
    fastcgi_param SCRIPT_NAME $fastcgi_script_name;
    fastcgi_intercept_errors on;
    fastcgi_ignore_client_abort off;
    fastcgi_connect_timeout 60;
    fastcgi_read_timeout 120;
    fastcgi_send_timeout 120;
    fastcgi_buffer_size 128k;
    fastcgi_buffers 4 256k;
    fastcgi_busy_buffers_size 256k;
    fastcgi_temp_file_write_size 256k;
  }
  location ~/\.hta {
    deny all;
  }
}

EOF_VHOST

cat << "EOF_PARAMS" > /etc/nginx/fastcgi_params
fastcgi_param  QUERY_STRING       $query_string;
fastcgi_param  REQUEST_METHOD     $request_method;
fastcgi_param  CONTENT_TYPE       $content_type;
fastcgi_param  CONTENT_LENGTH     $content_length;

fastcgi_param  SCRIPT_NAME        $fastcgi_script_name;
fastcgi_param  REQUEST_URI        $request_uri;
fastcgi_param  DOCUMENT_URI       $document_uri;
fastcgi_param  DOCUMENT_ROOT      $document_root;
fastcgi_param  SERVER_PROTOCOL    $server_protocol;
fastcgi_param  REQUEST_SCHEME     $scheme;
fastcgi_param  HTTPS              $https if_not_empty;

fastcgi_param  GATEWAY_INTERFACE  CGI/1.1;
fastcgi_param  SERVER_SOFTWARE    nginx/$nginx_version;

fastcgi_param  REMOTE_ADDR        $remote_addr;
fastcgi_param  REMOTE_PORT        $remote_port;
fastcgi_param  SERVER_ADDR        $server_addr;
fastcgi_param  SERVER_PORT        $server_port;
fastcgi_param  SERVER_NAME        $server_name;

# PHP only, required if PHP was built with --enable-force-cgi-redirect
fastcgi_param  REDIRECT_STATUS    200;

EOF_PARAMS
ln -s /etc/nginx/sites-available/${domain}.conf /etc/nginx/sites-enabled/${domain}.conf

cat <<"EOF_NGINX" > /etc/nginx/nginx.conf
user www-data;
worker_processes auto;
pid /run/nginx.pid;

events {
	worker_connections 768;
	# multi_accept on;
}

http {

	sendfile on;
	tcp_nopush on;
	tcp_nodelay on;
	keepalive_timeout 65;
	types_hash_max_size 2048;
	server_tokens off;

	include /etc/nginx/mime.types;
	default_type application/octet-stream;

	access_log /var/log/nginx/access.log;
	error_log /var/log/nginx/error.log;

	gzip on;
	gzip_disable "msie6";

	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}
EOF_NGINX

rm /etc/nginx/sites-enabled/default -f

cat <<"EOF_POOL" > /etc/php/7.0/fpm/pool.d/${domain}.conf
[${domain}]
listen = /var/run/${domain}.sock
listen.allowed_clients = 127.0.0.1
listen.owner = www-data
listen.mode = 660
listen.group = www-data
user = www-data
group = www-data

pm = ondemand
pm.max_children = 5
pm.max_requests = 200
pm.process_idle_timeout=10s

php_admin_value[open_basedir] = /mnt/efs/html:/usr/share/php:/tmp:/usr/share/phpmyadmin:/etc/phpmyadmin:/var/lib/phpmyadmin
php_admin_value[session.save_path] = /mnt/efs/html/tmp
php_admin_value[upload_tmp_dir] = /mnt/efs/html/tmp
clear_env = no
env[DB_ENDPOINT] = "${database}"
env[REDIS_ENDPOINT] = "${redis}"
EOF_POOL

if [ -d "/mnt/efs/html" ]; then
  chown www-data:www-data /mnt/efs/html -R
fi

echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf
echo "fs.file-max = 4000000" >> /etc/sysctl.conf

sed -i "s/; cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/" /etc/php/7.0/fpm/php.ini

systemctl start php7.0-fpm
systemctl enable php7.0-fpm
systemctl reload php7.0-fpm

snap start amazon-ssm-agent

systemctl restart nginx
systemctl enable nginx
