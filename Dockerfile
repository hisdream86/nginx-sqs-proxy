FROM openresty/openresty:1.21.4.1-6-buster

RUN apt update && \
    apt install -y libssl-dev luarocks && \
    luarocks install openssl 0.8.2-1 && \
    luarocks install lua-resty-http && \
    luarocks install penlight && \
    rm -rf /var/lib/apt/lists/*
COPY conf/nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY conf/sqs-proxy.conf /etc/nginx/conf.d/sqs-proxy.conf
COPY lua/ /etc/lua
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]

STOPSIGNAL SIGQUIT