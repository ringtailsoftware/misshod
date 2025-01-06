#!/bin/bash

PORT=2022

docker build -t sshd . && \
echo "ssh testuser@localhost -p 2022" && \
echo "password = passwork" && \
docker run -v $(pwd)/etc_dropbear:/etc/dropbear -v $(pwd)/dotssh:/home/myuser/.ssh -it -p $PORT:22 sshd
#docker run -v $(pwd)/etc_dropbear:/etc/dropbear -v $(pwd)/dotssh:/home/myuser/.ssh -it sshd /bin/sh

