./programs/pkey/gen_key type=rsa rsa_keysize=4096 filename="./ca_key.pem"
./programs/x509/cert_write selfsign=1 issuer_key="./ca_key.pem" issuer_name="CN=My Root CA,O=My Organization,C=US" not_before=20240101000000 not_after=20350101000000 output_file="./ca_cert.pem"
./programs/pkey/gen_key type=rsa rsa_keysize=4096 filename="./server_key.pem"
./programs/x509/cert_req filename="./server_key.pem" output_file="./server.csr" subject_name="CN=server,O=My Organization,C=US"
./programs/x509/cert_write issuer_key="./ca_key.pem" issuer_name="CN=My Root CA,O=My Organization,C=US" request_file="server.csr" subject_name="CN=server,O=My Organization,C=US" output_file="./server_cert.pem" not_before=20250101000000 not_after=20270101000000
./programs/pkey/gen_key type=rsa rsa_keysize=4096 filename="./client_key.pem"
./programs/x509/cert_req filename="./client_key.pem" output_file="./client_csr.pem" subject_name="CN=client,O=My Organization,C=US"
./programs/x509/cert_write issuer_key="./ca_key.pem" issuer_name="CN=My Root CA,O=My Organization,C=US" request_file="./client_csr.pem" subject_name="CN=client,O=My Organization,C=US" output_file="./client_cert.pem" not_before=20250101000000 not_after=20270101000000
./programs/x509/cert_app mode=file filename="./server_cert.pem" ca_file="./ca_cert.pem"
./programs/x509/cert_app mode=file filename="./client_cert.pem" ca_file="./ca_cert.pem"
