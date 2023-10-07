FROM openresty/openresty:1.21.4.1-6-buster

RUN apt update && \
    apt install -y libssl-dev luarocks && \
    luarocks install openssl 0.8.2-1 && \
    luarocks install lua-resty-http && \
    luarocks install penlight && \
    rm -rf /var/lib/apt/lists/*

COPY nginx/nginx.conf /usr/local/openresty/nginx/conf/nginx.conf
COPY nginx/sqs-proxy.conf /etc/nginx/conf.d/sqs-proxy.conf
COPY nginx/lua/ /etc/lua
