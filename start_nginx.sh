#!/bin/bash

app="nginx" 

if [ "$#" -ne 1 ]; then
    echo "requires interface parameter. Use: ./start_$app.sh ethX"
    exit -1
fi

intf=$1
echo Starting $app on interface $intf

/usr/local/nginx_dpdk/nginx &

#sleep 1
#ifconfig fp0 $2
#sleep 1

#iptables -A FORWARD -i $intf -j DROP
#iptables -A INPUT -i $intf -j DROP
#ip6tables -A FORWARD -i $intf -j DROP
#ip6tables -A INPUT -i $intf -j DROP
#ifconfig $intf -arp
#ip addr flush dev $intf

