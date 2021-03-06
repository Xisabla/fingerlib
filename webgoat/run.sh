#!/usr/bin/env bash
# -*- coding: utf-8 -*-

# fingerlib-server entrypoint script

chown -R root:root /out

# Run tshark
tshark -w /out/capture.pcap -i eth0 & 

# Run webgoat
java \
    -Duser.home=/home/webgoat \
    -Dfile.encoding=UTF-8 \
    --add-opens java.base/java.lang=ALL-UNNAMED \
    --add-opens java.base/java.util=ALL-UNNAMED \
    --add-opens java.base/java.lang.reflect=ALL-UNNAMED \
    --add-opens java.base/java.text=ALL-UNNAMED \
    --add-opens java.desktop/java.beans=ALL-UNNAMED \
    --add-opens java.desktop/java.awt.font=ALL-UNNAMED \
    --add-opens java.base/sun.nio.ch=ALL-UNNAMED \
    --add-opens java.base/java.io=ALL-UNNAMED \
    --add-opens java.base/java.util=ALL-UNNAMED \
    -Drunning.in.docker=true \
    -Dwebgoat.host=0.0.0.0 \
    -Dwebwolf.host=0.0.0.0 \
    -Dwebgoat.port=8080 \
    -Dwebwolf.port=9090 \
    -jar webgoat.jar

chown -R 1000:1000 /out
chmod 777 /out/capture.pcap
