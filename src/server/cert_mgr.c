#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <c_stl_lib.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>
#include <mbedtls/ssl_ticket.h>
#include <mbedtls/ssl_cache.h>
#include <mbedtls/platform.h>
#include "cert_mgr.h"
#include "../text_in_color.h"
#ifdef WIN32
#include <windows.h>
#else
#include <dirent.h>
#endif

static int compare_key(const void *left, const void *right) {
	const char* l = (const char*)left;
	const char* r = (const char*)right;
	return strcmp(l, r);
}

static void destroy_object(void *obj) {
	if (obj) {
		void *str = *((void **)obj);
		if (str) {
			free(str);
		}
	}
}

typedef struct certmgr {
	struct cstl_map *cert_datas;
}certmgr_t;

struct certmgr * certmgr_create() {
	struct certmgr *mgr= (struct certmgr *)calloc(1, sizeof(certmgr_t));
	mgr->cert_datas = cstl_map_new(compare_key, NULL, NULL);
	return mgr;
}

void certmgr_destroy(struct certmgr *mgr) {
	struct cstl_iterator* it = cstl_map_new_iterator(mgr->cert_datas);
	const void* element;
	while ((element = it->next(it))) {
		const struct cert_data * value = it->current_value(it);
		if (value->cert) {free(value->cert);}
	}
	cstl_map_delete_iterator(it);
	cstl_map_delete(mgr->cert_datas);
	free(mgr);
}

void certmgr_add_pem(struct certmgr *mgr, const char* domain, uint16_t version, char* pem, size_t len) {
	struct cert_data obj;
	memset(&obj, 0x00, sizeof(struct cert_data));
	obj.version = version;
	obj.pem = (char*)malloc(len);
	memcpy(obj.pem, pem, len);
	obj.len = len;
	cstl_map_insert(mgr->cert_datas, domain, strlen(domain) + 1, (void*)&obj, sizeof(cert_data_t));
}

int certmgr_query_version(struct certmgr *mgr, char* domain, uint16_t *version) {
	struct cert_data * obj = NULL;
	if (mgr == NULL || domain == NULL) {
		return -1;
	}
	obj = (struct cert_data *) cstl_map_find(mgr->cert_datas, domain);
	if (obj == NULL) {
		return -1;
	}
	*version = obj->version;
	return 0;
}

struct cert_data * get_cert_info(struct certmgr *mgr, const char* domain) {
	struct cert_data * obj = NULL;
	if (mgr == NULL || domain == NULL) {
		return NULL;
	}
	return (struct cert_data *) cstl_map_find(mgr->cert_datas, domain);
}

void print_probe_domain(struct certmgr *mgr) {
	struct cstl_iterator* it = cstl_map_new_iterator(mgr->cert_datas);
	const void* element;
	while ((element = it->next(it))) {
		const char * key  = it->current_key(it);
		const struct cert_data * obj = it->current_value(it);
		xtrace(text_color_white,"print_probe_domain: %s  ver:%04X  len:%d", key, obj->version, obj->len);
	}
	cstl_map_delete_iterator(it);
}

int certmgr_steal_cert(struct certmgr *mgr, const char* host, uint16_t* tlsver) {
	int ret;
	mbedtls_net_context server_fd;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	// 1. 初始化
	const char *pers = "ssl_client1";
	mbedtls_net_init(&server_fd);
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
	if ((ret = mbedtls_net_connect(&server_fd, host, "443", MBEDTLS_NET_PROTO_TCP)) != 0) {
		printf("连接失败: -0x%x\n", -ret);
	}
	mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE); // **不验证**服务器证书 (MBEDTLS_SSL_VERIFY_NONE)
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);  // 设置随机数生成器
	if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) goto exit;
	mbedtls_ssl_set_hostname(&ssl, host);
	mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
	// 5. 分步握手以获取数据
	while (ssl.private_state != MBEDTLS_SSL_HANDSHAKE_OVER) {
		ret = mbedtls_ssl_handshake_step(&ssl);
		if (ret != 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			printf("握手出错: -0x%x\n", -ret);
			break;
		}
	}

	//获取证书
	const struct mbedtls_x509_crt * crt = mbedtls_ssl_get_peer_cert(&ssl);
	if (crt != NULL) {
		*tlsver = ssl.private_tls_version;
		struct cert_data obj;
		obj.version = ssl.private_tls_version;
		obj.cert = malloc(sizeof(struct mbedtls_x509_crt));
		mbedtls_x509_crt_init(obj.cert);
		mbedtls_x509_crt_parse(obj.cert, crt->raw.p, crt->raw.len);
		obj.len = crt->raw.len;
		cstl_map_insert(mgr->cert_datas, host, strlen(host) + 1, (void*)&obj, sizeof(cert_data_t));
	}

exit:
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_net_free(&server_fd);
	return 0;
}

int certmgr_add_cert(struct certmgr *mgr, const char* host, uint16_t tlsver, const char* cert){
	struct cert_data obj;
	obj.version = tlsver;
	obj.cert = malloc(sizeof(struct mbedtls_x509_crt));
	mbedtls_x509_crt_init(obj.cert);
	mbedtls_x509_crt_parse(obj.cert, (const unsigned char *)cert, strlen(cert) + 1);
	obj.len = strlen(cert) + 1;
	return cstl_map_insert(mgr->cert_datas, host, strlen(host) + 1, (void*)&obj, sizeof(cert_data_t));
}