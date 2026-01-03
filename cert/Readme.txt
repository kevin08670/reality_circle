2.1. 生成 CA 根密钥和根证书
//生成 CA 根密钥 (ca_key.pem)
./programs/pkey/gen_key type=rsa rsa_keysize=4096 filename=ca_key.pem

//生成 CA 根证书 (ca_cert.pem) 
./programs/x509/cert_write selfsign=1 issuer_key=ca_key.pem issue_name="CN=My Root CA,O=My Organization,C=US" not_before=20240101000000 not_after=20350101000000 output_file=ca_cert.pem

2.2 生成服务器密钥和证书签名请求 (CSR)
//生成服务器私钥 (server_key.pem)
./programs/pkey/gen_key type=rsa rsa_keysize=4096 filename=server_key.pem

//生成服务器证书签名请求 (server.csr) 
./programs/x509/cert_req filename=server_key.pem output_file=server.csr subject_name="CN=server,O=My Organization,C=US"


2.3. 签署服务器证书
//生成服务器证书 (server_cert.pem)
./programs/x509/cert_write issuer_key=ca_key.pem issuer_name="CN=My Root CA,O=My Organization,C=US" request_file=server.csr subject_name="CN=server,O=My Organization,C=US" output_file=server_cert.pem not_before=20240101000000 not_after=20250101000000


2.4. 生成客户端私钥和证书签名请求 (CSR)
//生成客户端私钥 (client_key.pem)
./programs/pkey/gen_key type=rsa rsa_keysize=4096 filename=client_key.pem

//生成客户端证书签名请求（client_csr.pem）
./programs/x509/cert_req filename=client_key.pem output_file=client_csr.pem subject_name="CN=client,O=My Organization,C=US"

2.5. 签署客户端证书
//生成客户端证书 (client_cert.pem)
./programs/x509/cert_write issuer_key=ca_key.pem issuer_name="CN=My Root CA,O=My Organization,C=US" request_file=client_csr.pem subject_name="CN=client,O=My Organization,C=US" output_file=client_cert.pem not_before=20240101000000 not_after=20250101000000

2.6. 验证生成的证书
//验证服务器证书
./programs/x509/cert_app mode=file filename=server_cert.pem ca_file=ca_cert.pem

//验证客户端证书
./programs/x509/cert_app mode=file filename=client_cert.pem ca_file=ca_cert.pem
