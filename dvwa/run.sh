#!/usr/bin/env bash
# -*- coding: utf-8 -*-

# fingerlib-server entrypoint script

chown -R root:root /out

# Run tshark
tshark -w /out/capture.pcap -i eth0 & 

# Run dvwa
/main.sh

chown -R 1000:1000 /out
chmod 777 /out/capture.pcap

chown -R mysql:mysql /var/lib/mysql /var/run/mysqld