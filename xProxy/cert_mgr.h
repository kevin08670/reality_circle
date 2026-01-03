#ifndef __CERT_MANAGER_H__
#define __CERT_MANAGER_H__
#include <stdint.h>

struct certmgr;
struct certmgr* certmgr_create();
void certmgr_destroy(struct certmgr* mgr);
int certmgr_update_ssl(struct certmgr *mgr, void *ssl, const char *domain);
void add_cert_psk(struct certmgr *mgr, const char* domain, const char* cert, const char* key, const char* pwd);
void get_clientHello(struct certmgr *mgr,  char* domain, char** data, size_t* len);

struct shcrtmgr;
struct shcrtmgr * shcrtmgr_create();
void shcrtmgr_destroy(struct shcrtmgr* mgr);
void add_shcrt(struct shcrtmgr *mgr, const char* domain, const char* data, size_t len);
int get_shcrt_data(struct shcrtmgr *mgr, char* domain, char** data, size_t* len);

#endif // __CERT_MANAGER_H__