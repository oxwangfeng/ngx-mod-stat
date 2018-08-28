ngx_mod-stat
====
基于nginx module方式开发的统计模块


安装
    ./configure --prefix=/usr/local/nginx-1.8.0 --add-module=/path/to/ngx-mod-stat/
    ./configure --prefix=/usr/local/nginx --add-module=/export/cdncode/nginx-1.8.0/src/ngx-mod-stat/ --add-module=/export/cdncode/nginx-1.8.0/bundle/echo-nginx-module


指令

jinx_stat
syntax: jinx_stat on|off
default: off
context: http, server

jinx_stat_uri
syntax: jinx_stat_uri uri
default: -
context: server

jinx_stat_out
syntax: jinx_stat_out
default: -
context: location

jinx_stat_max
syntax: jinx_stat_max size
default: -
context: http, server


使用

...
http {
     ...
     jinx_stat on;
     jinx_stat_max 20;
     ...
     server {
          ...
     }
     server {
          ...
          jinx_stat off
     }
     server {
          server_name "jinx.jd.local"
          location /status {
               jinx_stat_out;
          }
     }

    upstream gw_cdn {
            server 192.168.178.40:8099;
            server 192.168.178.17:8099;
    }

    server
    {
            listen                 80; 
            server_name            gw.cdn.jd.local;
            jinx_stat_uri          /api;
            jinx_stat_uri          /test;
            jinx_stat_uri          /a; 
            location / { 
                    proxy_pass http://gw_cdn;
                    proxy_set_header Host $host;
            }   
    }
}


get status use http request
    http http://nginx_ip:nginx_port/status Host:jinx.jd.local
