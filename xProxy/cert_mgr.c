#include "cert_mgr.h"
#include <time.h>
#include <string.h>
#include <assert.h>
#include <c_stl_lib.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <mbedtls/ssl.h>
#include <json.h>

#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>
#include <mbedtls/ssl_ticket.h>
#include <mbedtls/ssl_cache.h>
#include <mbedtls/platform.h>

#include "../mycert.h"

#include "../text_in_color.h"
#ifdef WIN32
#include <windows.h>
#else
#include <dirent.h>
#endif

typedef struct cert_psk {
	mbedtls_x509_crt cert;
	mbedtls_pk_context psk;
}cert_psk_t;

typedef struct certmgr {
	struct cstl_map *probe_certs;
	unsigned char target_server_hello[65535];
	size_t  target_server_hello_len;
}certmgr_t;

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

static void readFileContext(const char* filepath, char** context) {
	FILE *fp = fopen(filepath, "r");
	if (fp) {
		fseek(fp, 0, SEEK_END);
		long fileSize = ftell(fp);
		rewind(fp);
		*context = malloc(fileSize + 1);
		if (*context) {
			fread(*context, 1, fileSize, fp);
			(*context)[fileSize] = '\0';
			printf("%s\n%s\n", filepath, *context);
		}
		fclose(fp);
	}
}
static void safeFree( void * p ) {
	if (p) {
		free(p);
		p = NULL;
	}
}

struct certmgr * certmgr_create() {
	struct certmgr *mgr = NULL;
	mgr = (struct certmgr *) calloc(1, sizeof(certmgr_t));
	mgr->probe_certs = cstl_map_new(compare_key, NULL, NULL);
#ifdef WIN32
	WIN32_FIND_DATAA findData;
	HANDLE hFind = FindFirstFileA(".\\cert\\*", &findData);
	if (hFind == INVALID_HANDLE_VALUE) {
		printf("路径未找到或无法打开。\n");
		return NULL;
	}
	do {
		if (strcmp(findData.cFileName, ".") != 0 && strcmp(findData.cFileName,"..") != 0) {
			if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				printf("\nDomain: %s\n", findData.cFileName);
				char cert_file[256] = { 0 };
				char key_file[256] = { 0 };
				char pwd_file[256] = { 0 };
				sprintf(cert_file, ".\\cert\\%s\\server_cert.pem", findData.cFileName);
				sprintf(key_file, ".\\cert\\%s\\server_key.pem", findData.cFileName);
				sprintf(pwd_file, ".\\cert\\%s\\server_pwd.text", findData.cFileName);
				char * server_cert = NULL;
				char * server_key = NULL;
				char * server_pwd = NULL;
				readFileContext(cert_file, &server_cert);
				readFileContext(key_file, &server_key);
				readFileContext(pwd_file, &server_pwd);
				add_cert_psk(mgr, findData.cFileName, server_cert, server_key, server_pwd);
				safeFree(server_cert);
				safeFree(server_key);
				safeFree(server_pwd);
			}
		}
	} while (FindNextFileA(hFind, &findData));
	FindClose(hFind);
#else
	struct dirent *entry;
	DIR *dp = opendir("./cert/"); // 打开当前目录
	if (dp != NULL) {
		while ((entry = readdir(dp)) != NULL && entry->d_name[0] != '.') {
			printf("domain cert dir:%s\n", entry->d_name);
			char cert_file[1024] = { 0 };
			char key_file[1024] = { 0 };
			char pwd_file[1024] = { 0 };
			sprintf(cert_file, "./cert/%s/server_cert.pem", entry->d_name);
			sprintf(key_file, "./cert/%s/server_key.pem", entry->d_name);
			sprintf(pwd_file, "./cert/%s/server_pwd.text", entry->d_name);
			char * server_cert = NULL;
			char * server_key = NULL;
			char * server_pwd = NULL;
			readFileContext(cert_file, &server_cert);
			readFileContext(key_file, &server_key);
			readFileContext(pwd_file, &server_pwd);
			add_cert_psk(mgr, entry->d_name, server_cert, server_key, server_pwd);
			safeFree(server_cert);
			safeFree(server_key);
			safeFree(server_pwd);
		}
		closedir(dp);
	}
#endif

	//certmgr_clientHello( mgr );
	return mgr;
}

void certmgr_destroy(struct certmgr *mgr) {
	cstl_map_delete(mgr->probe_certs);
	free(mgr);
}

void add_cert_psk(struct certmgr *mgr, const char* domain, const char* cert, const char* key, const char* pwd) {
	struct cert_psk obj;
	mbedtls_x509_crt_init(&obj.cert);
	mbedtls_pk_init(&obj.psk);
	int ret = mbedtls_x509_crt_parse(&obj.cert, (const unsigned char *)cert, strlen(cert) + 1);
	if (ret != 0) { fprintf(stderr, "crt_parse failed: %d\n", ret); return; }
	ret = mbedtls_pk_parse_key(&obj.psk, (const unsigned char *)key, strlen(key) + 1, (const unsigned char *)pwd, strlen(pwd), NULL, 0);
	if (ret != 0) { fprintf(stderr, "pk_parse_key failed: %d\n", ret); return; }
	cstl_map_insert(mgr->probe_certs, domain, strlen(domain)+1, (void*)&obj, sizeof(cert_psk_t));
}

//给SSL通道添加相应的证书
int certmgr_update_ssl(struct certmgr *mgr, void *ssl,  const char *domain) {
	struct cert_psk * obj = NULL;
	if (mgr == NULL || domain == NULL) {
		return -1;
	}
	obj = (struct cert_psk *) cstl_map_find(mgr->probe_certs, domain);
	if (obj == NULL) {
		return -1;
	}
	return mbedtls_ssl_set_hs_own_cert((mbedtls_ssl_context*)ssl, &obj->cert, &(obj->psk));
}

// 调试回调函数：用于打印握手过程中的详细数据（包括 Server Hello）
static void my_debug(void *ctx, int level, const char *file, int line, const char *str) {
	((void)level);
	fprintf((FILE *)ctx, "%s:%04d: %s", file, line, str);
}

// mbedTLS 随机数生成回调 (⚠️ 警告: 测试/示例代码，使用了硬编码的 13，非安全随机数)
int my_mbedtls_ctr_drbg_random(void *p_rng, unsigned char *output, size_t output_len)
{
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	mbedtls_ctr_drbg_context *ctx = (mbedtls_ctr_drbg_context *)p_rng;
	// 实际应使用 mbedtls_platform_random() 或硬件特有代码
	for (size_t i = 0; i < output_len; i++) {
		// ⚠️ 在非测试环境中，请勿使用 C 标准库的 rand()
		output[i] = (unsigned char)(rand() % 256); // 简单硬编码，用于非安全测试
	}
	return 0;
}

int certmgr_clientHello(struct certmgr *mgr ) {
	int ret;
	mbedtls_net_context server_fd;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	//mbedtls_x509_crt cacert;

	// 1. 初始化
	const char *pers = "ssl_client1";
	mbedtls_net_init(&server_fd);
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	//mbedtls_x509_crt_init(&cacert);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));

	// 3. 连接
	if ((ret = mbedtls_net_connect(&server_fd, "google.com", "443", MBEDTLS_NET_PROTO_TCP)) != 0) {
		printf("连接失败: -0x%x\n", -ret);
		goto exit;
	}

	// 初始化 Session Cache
	//mbedtls_ssl_cache_context cache;
	//mbedtls_ssl_conf_session_tickets(&conf, MBEDTLS_SSL_SESSION_TICKETS_ENABLED); // 启用 session tickets
	//mbedtls_ssl_cache_init(&cache); // 初始化 session cache
	//mbedtls_ssl_cache_set_max_entries(&cache, 100); // 设置最大条目数
	//mbedtls_ssl_conf_session_cache(&conf, (void*)&cache, my_cache_get, my_cache_set); // 设置 session cache 的回调函数

	// 使用自带的测试证书 (CA 证书)
	//ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *)c_mbedtls_test_cas_pem, strlen(c_mbedtls_test_cas_pem) + 1);
	//if (ret != 0) { fprintf(stderr, "crt_parse failed: %d\n", ret); return; }
	// 设置默认配置为客户端模式
	mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);

	// 强制限制为 TLS 1.3: (当前被注释)
	mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4); // TLS 1.3
	mbedtls_ssl_conf_max_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4); // TLS 1.3

	// 4. 配置
	//mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	//mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
	//mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	//mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE); // **不验证**服务器证书 (MBEDTLS_SSL_VERIFY_NONE)
	//mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL); // 设置 CA 证书链
	mbedtls_ssl_conf_rng(&conf, my_mbedtls_ctr_drbg_random, &ctr_drbg);  // 设置随机数生成器


	if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) goto exit;
	mbedtls_ssl_set_hostname(&ssl, "google.com");
	mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

	// 5. 分步握手以获取数据
	printf("开始握手...\n");
	while (ssl.private_state != MBEDTLS_SSL_HANDSHAKE_OVER) {
		ret = mbedtls_ssl_handshake_step(&ssl);
		if (ret != 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			printf("握手出错: -0x%x\n", -ret);
			goto exit;
		}
		if (ssl.private_state == MBEDTLS_SSL_ENCRYPTED_EXTENSIONS) {
			printf("\n[成功捕获] google.com Server Hello 数据:%d\n", ssl.private_in_msglen + 5);
			memcpy(mgr->target_server_hello, ssl.private_in_hdr, ssl.private_in_msglen + 5);
			mgr->target_server_hello_len = ssl.private_in_msglen + 5 ;
			char szout[1024 * 3 + 1] = { 0 };
			for (size_t i = 0; i < ssl.private_in_msglen + 5 && i < 1024; i++) {
				sprintf(&szout[i * 3], ((i+1) % 16)?"%02X ": "%02X\n", mgr->target_server_hello[i]);
			}
			printf(szout);
			printf("\n");
		}
	}
	printf("握手完成！\n");
	printf("协商的密码套件: %s\n", mbedtls_ssl_get_ciphersuite(&ssl));

exit:
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	mbedtls_net_free(&server_fd);
	return 0;
}

void get_clientHello(struct certmgr *mgr, char* domain, char** data, size_t* len) {
	*data = &mgr->target_server_hello[0];
	*len = mgr->target_server_hello_len;
}

typedef struct shcrt_data {
	unsigned char * data;
	size_t  len;
}shcrt_data_t;

typedef struct shcrtmgr {
	struct cstl_map *shcrt_datas;
}shcrtmgr_t;

struct shcrtmgr * shcrtmgr_create() {
	struct shcrtmgr *mgr = NULL;
	mgr = (struct certmgr *) calloc(1, sizeof(shcrtmgr_t));
	mgr->shcrt_datas = cstl_map_new(compare_key, NULL, NULL);
	return mgr;
}

void shcrtmgr_destroy(struct shcrtmgr *mgr) {
	cstl_map_delete(mgr->shcrt_datas);
	free(mgr);
}

void add_shcrt(struct shcrtmgr *mgr, const char* domain, unsigned char* data, size_t len) {
	struct shcrt_data obj;
	obj.data = (unsigned char*)malloc(len);
	memcpy(obj.data, data, len);
	obj.len = len;
	cstl_map_insert(mgr->shcrt_datas, domain, strlen(domain) + 1, (void*)&obj, sizeof(shcrt_data_t));
}

int get_shcrt_data(struct shcrtmgr *mgr, char* domain, char** data, size_t* len) {
	struct shcrt_data * obj = NULL;
	if (mgr == NULL || domain == NULL) {
		return -1;
	}
	obj = (struct shcrt_data *) cstl_map_find(mgr->shcrt_datas, domain);
	if (obj == NULL) {
		return -1;
	}
	*data = obj->data;
	*len = obj->len;
	return 0;
}