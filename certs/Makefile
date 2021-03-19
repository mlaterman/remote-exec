default: certs

all: certs test-cert.pem

certs:  server-cert.pem  client-cert.pem

ca-server-key.pem:
	openssl req -x509 -newkey rsa:4096 -nodes -keyout ca-server-key.pem -out ca-server-cert.pem -days 365 \
		-subj "/C=XX/ST=Server/L=Server/O=Server Auth/CN=server-ca"

ca-client-key.pem:
	openssl req -x509 -newkey rsa:4096 -nodes -keyout ca-client-key.pem -out ca-client-cert.pem -days 365 \
		-subj "/C=XX/ST=Client/L=Client/O=Client Auth/CN=client-ca"

ca-test-key.pem:
	openssl req -x509 -newkey rsa:4096 -nodes -keyout ca-test-key.pem -out ca-test-cert.pem -days 365 \
		-subj "/C=XX/ST=Testing/L=Testing/O=Testing Auth/CN=test-ca"

server-cert.pem: ca-server-key.pem
	openssl req -newkey rsa:4096 -nodes -keyout server-key.pem -out server.csr \
		-subj "/C=XX/ST=Server/L=Server/O=Server/CN=server" -addext "subjectAltName = IP:127.0.0.1"
	openssl x509 -req -in server.csr -CA ca-server-cert.pem -CAkey ca-server-key.pem -out server-cert.pem -CAcreateserial -days 365 -extensions req_ext -extfile ssl.conf

client-cert.pem: ca-client-key.pem
	openssl req -newkey rsa:4096 -nodes -keyout client-key.pem -out client.csr \
		-subj "/C=XX/ST=Client/L=Client/O=Client/CN=client" -addext "subjectAltName = IP:127.0.0.1"
	openssl x509 -req -in client.csr -CA ca-client-cert.pem -CAkey ca-client-key.pem -out client-cert.pem -CAcreateserial -days 365 -extensions req_ext -extfile ssl.conf

test-cert.pem: ca-test-key.pem
	openssl req -newkey rsa:4096 -nodes -keyout test-key.pem -out test.csr \
		-subj "/C=XX/ST=Testing/L=Testing/O=Testing/CN=test" -addext "subjectAltName = IP:127.0.0.1"
	openssl x509 -req -in test.csr -CA ca-test-cert.pem -CAkey ca-test-key.pem -out test-cert.pem -CAcreateserial -days 365 -extensions req_ext -extfile ssl.conf

clean:
	rm -f *.csr *.pem *.srl
