#!/bin/bash
if [[ ! -f .env ]]; then
  echo "Missing required .env file, refer to README.md."
  exit 1
fi

source .env

if [[ "${EXTERNAL_HOSTNAME}" == "" ]]; then
  echo ".env file missing EXTERNAL_HOSTNAME"
  exit 1
fi
if [[ "${DOCKER_HTTP_PORT}" == "" ]]; then
  echo ".env file missing DOCKER_HTTP_PORT"
  exit 1
fi

CERT_DIR=./data/certs
mkdir -p "$CERT_DIR"

sudo certbot certonly --standalone --keep \
  -d "$EXTERNAL_HOSTNAME" \
  --http-01-port "$DOCKER_HTTP_PORT" || exit $?

sudo cp "/etc/letsencrypt/live/$EXTERNAL_HOSTNAME/cert.pem" \
        "/etc/letsencrypt/live/$EXTERNAL_HOSTNAME/privkey.pem" \
        "$CERT_DIR" || exit $?

sudo chown -R `id -u`:`id -g` "$CERT_DIR" || exit $?
sudo chmod 700 "$CERT_DIR" || exit $?
sudo chmod 600 "$CERT_DIR/cert.pem" "$CERT_DIR/privkey.pem" || exit $?

echo "Certificates copied to $CERT_DIR"
