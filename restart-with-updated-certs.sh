#!/bin/bash
docker-compose stop
./update-certs.sh
docker-compose start
