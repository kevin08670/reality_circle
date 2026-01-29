#ifndef __CERT_MANAGER_H__
#define __CERT_MANAGER_H__
#include <stdint.h>
#include <stddef.h>
typedef struct cert_data {
	uint16_t version;
	struct mbedtls_x509_crt * cert;
	char * pem;
	size_t  len;
}cert_data_t;

struct certmgr;
struct certmgr * certmgr_create();
void certmgr_destroy(struct certmgr* mgr);
void certmgr_add_pem(struct certmgr *mgr, const char* domain, uint16_t version, char* pem, size_t len);
int certmgr_query_version(struct certmgr *mgr, char* domain, uint16_t* version);
int certmgr_steal_cert(struct certmgr *mgr, const char* host, uint16_t* tlsver);
int certmgr_add_cert(struct certmgr *mgr, const char* host, uint16_t tlsver, const char* cert);
struct cert_data * get_cert_info(struct certmgr *mgr, const char* domain);
void print_probe_domain(struct certmgr *mgr);

#endif // __CERT_MANAGER_H__