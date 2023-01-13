if [[ $# != 1 ]]; then
  echo "Usage: $0 <domain-name>"
  exit 1
fi

DOMAIN="$1"
CERT_DIR=./data/certs
mkdir -p "$CERT_DIR"

sudo certbot certonly --standalone --keep \
  -d "$DOMAIN" \
  --http-01-port 8001 || exit $?

sudo cp "/etc/letsencrypt/live/$DOMAIN/cert.pem" \
        "/etc/letsencrypt/live/$DOMAIN/privkey.pem" \
        "$CERT_DIR" || exit $?

sudo chown -R `id -u`:`id -g` "$CERT_DIR"
sudo chmod -R 600 "$CERT_DIR"
