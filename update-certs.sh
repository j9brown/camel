if [[ $# != 2 ]]; then
  echo "Usage: $0 <domain-name> <http-port>"
  exit 1
fi

DOMAIN="$1"
HTTP_PORT="$2"

CERT_DIR=./data/certs
mkdir -p "$CERT_DIR"

sudo certbot certonly --standalone --keep \
  -d "$DOMAIN" \
  --http-01-port "$HTTP_PORT" || exit $?

sudo cp "/etc/letsencrypt/live/$DOMAIN/cert.pem" \
        "/etc/letsencrypt/live/$DOMAIN/privkey.pem" \
        "$CERT_DIR" || exit $?

sudo chown -R `id -u`:`id -g` "$CERT_DIR" || exit $?
sudo chmod 700 "$CERT_DIR" || exit $?
sudo chmod 600 "$CERT_DIR/cert.pem" "$CERT_DIR/privkey.pem" || exit $?

echo "Certificates copied to $CERT_DIR"
