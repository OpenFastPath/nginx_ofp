#!/bin/bash
if [ "$#" -ne 1 ]; then
    echo "requires an interface parameter. Use: ./start_webserver.sh ethX"
    exit -1
fi

intf=$1
if test "X$intf" = "X"; then intf=eth0; fi

app="nginx"
echo "Stopping $app"

kill -9 `cat /usr/local/nginx_dpdk/nginx.pid`

ps -e | grep '\s\+nginx$' | awk '{print $1}' | xargs kill -9

#ifconfig $intf down
#iptables -D FORWARD -i $intf -j DROP
#iptables -D INPUT -i $intf -j DROP
#ip6tables -D FORWARD -i $intf -j DROP
#ip6tables -D INPUT -i $intf -j DROP
#ifconfig $intf arp
#
#ifconfig eth0 192.168.1.4/24 up
mv /usr/local/nginx_dpdk/nginx.pid /usr/local/nginx_dpdk/nginx.pid.bk
