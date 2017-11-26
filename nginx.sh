#!/bin/bash
. _variables

yum -y install nginx php-fpm

mkdir /etc/nginx/sites-available
mkdir /etc/nginx/sites-enabled

userdel -Z -r -f httpd
userdel -Z -r -f www-data
groupadd -g ${WWW_DATA_GID} ${WWW_DATA_GROUP_NAME}
useradd -d ${WWW_DATA_HOMEDIR} -m -u ${WWW_DATA_UID} -s /bin/false ${WWW_DATA_USER_NAME}
semanage fcontext -a -t https_sys_content ${WWW_DATA_HOMEDIR}
restorecon -v ${WWW_DATA_HOMEDIR}

if [ -f ${DEST_FILE} ]; then
    cp -a ${DEST_FILE} ${DEST_FILE}.backup-$(date +%F)
fi

cat > /etc/nginx/nginx.conf <<EOF
worker_processes      2;
worker_priority      15;

user ${WWW_DATA_USER_NAME};
pid /var/run/nginx.pid;

events {
  worker_connections 768;
  #multi_accept on;
}

http {
  client_max_body_size     20m;
  client_body_timeout      5s;
  client_header_timeout    5s;
  keepalive_timeout       75s;
  send_timeout            15s;
  #default_type            application/octet-stream;
  charset                 utf-8;
  gzip                    off;
  gzip_http_version       1.0;
  gzip_static             on;
  gzip_vary               on;
  gzip_proxied            any;
  gzip_comp_level	      1;
  gzip_types		    text/plain text/css text/xml text/javascript image/bmp application/javascript application/x-javascript;
  gzip_buffers 16 8k;
  ignore_invalid_headers  on;
  keepalive_requests      50;
  keepalive_disable       none;
  max_ranges              1;
  msie_padding            off;
  open_file_cache         max=1000 inactive=2h;
  open_file_cache_errors  on;
  open_file_cache_min_uses  1;
  open_file_cache_valid   1h;
  output_buffers          1 512;
  postpone_output         1440;
  read_ahead              512K;
  recursive_error_pages   on;
  reset_timedout_connection on;
  sendfile                on;
  server_tokens           off;
  server_name_in_redirect off;
  source_charset          utf-8;
  tcp_nodelay             on;
  tcp_nopush              off;
  limit_req_zone          $binary_remote_addr  zone=gulag:1m   rate=60r/m;
  types_hash_max_size 2048;
  # server_tokens          off;
  # server_names_hash_bucket_size 64;
  # server_name_in_redirect off;
  access_log              /var/log/nginx/access.log;
  error_log               /var/log/nginx/error.log;
  #passenger_root         /usr;
  #passenger_ruby         /usr/bin/ruby;
  include                 /etc/nginx/ssl.conf
  include                 /etc/nginx/mime.types;
  include                 /etc/nginx/sites-enabled/*;
}
EOF

cat > /etc/nginx/ssl.conf <<EOF
  # global SSL options with Perfect Forward Secrecy (PFS) high strength ciphers
  # first. PFS ciphers are those which start with ECDHE which means (EC)DHE
  # which stands for (Elliptic Curve) Diffie-Hellman Ephemeral.

  # RSA ciphers
  ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:AES256-GCM-SHA384;
  # ECDSA ssl ciphers; google chrome prefered order, 128bit most prefered
  #ssl_ciphers ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA;

  ssl_ecdh_curve secp384r1;            # 384 bit prime modulus curve efficiently supports ECDHE ssl_ciphers up to a SHA384 hash
  #ssl_session_timeout 5m; # SPDY timeout=180sec, keepalive=20sec; connection close=session expires
  #ssl on;
  ssl_session_cache shared:SSL:1m;
  ssl_prefer_server_ciphers on;          # the preferred ciphers are listed on the server by "ssl_ciphers"
  ssl_protocols TLSv1.2 TLSv1.1 TLSv1;   # protocols, the order is unimportant
  ssl_session_timeout 128s;              # how long before the client and server must renegotiate the ssl key
  ssl_session_tickets off;
  ssl_dhparam /etc/ssl/certs/dhparam.pem;
EOF
