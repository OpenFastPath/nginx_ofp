#!/bin/bash

app="nginx" 

if [ "$#" -ne 1 ]; then
    echo "requires interface parameter. Use: ./start_$app.sh ethX"
    exit -1
fi

intf=$1
echo Starting $app on interface $intf

# Find number of queues from config file
CONFIG_FILE=%%NGX_CONF_PREFIX%%/nginx.conf
line=$(grep -m 1 '^\s*worker_processes' $CONFIG_FILE)
if [ -n "$line" ]; then
    NUM_QUEUES=$(echo $line | sed -r 's/^\s*worker_processes\s+([0-9])\s*;/\1/')
    echo "Found $NUM_QUEUES worker_processes"
    export NUM_QUEUES
fi

%%NGX_SBIN_PATH%%/nginx &

#sleep 1
#ifconfig fp0 $2
#sleep 1

#iptables -A FORWARD -i $intf -j DROP
#iptables -A INPUT -i $intf -j DROP
#ip6tables -A FORWARD -i $intf -j DROP
#ip6tables -A INPUT -i $intf -j DROP
#ifconfig $intf -arp
#ip addr flush dev $intf

