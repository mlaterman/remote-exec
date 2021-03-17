default: certs

all: certs test-key.pem

certs:  server-key.pem  client-key.pem

server-key.pem:
	openssl req -x509 -newkey rsa:4096 -nodes -keyout server-key.pem -out server-cert.pem -days 365 \
		-subj "/C=XX/ST=Server/L=Server/O=Server/CN=localhost" -addext "subjectAltName = IP:127.0.0.1"

client-key.pem:
	openssl req -x509 -newkey rsa:4096 -nodes -keyout client-key.pem -out client-cert.pem -days 365 \
		-subj "/C=XX/ST=Client/L=Client/O=Client/CN=client"

test-key.pem:
	openssl req -x509 -newkey rsa:4096 -nodes -keyout test-key.pem -out test-cert.pem -days 365 \
		-subj "/C=XX/ST=Testing/L=Testing/O=Testing/CN=test"

clean:
	rm -f *.csr *.pem
