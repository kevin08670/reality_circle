#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "configure.h"

char *optarg = NULL;
int getopt(int argc, char **argv, const char *opts) {
	static int sp = 1;
	static int opterr = 1;
	static int optind = 1;
	static int optopt;
	register int c;
	register char *cp;
	if (sp == 1)
		if (optind >= argc || argv[optind][0] != '-' || argv[optind][1] == '\0')
			return(-1);
		else if (strcmp(argv[optind], "--") == 0) {
			optind++;
			return(-1);
		}
	optopt = c = argv[optind][sp];
	if (c == ':' || (cp = (char*)strchr(opts, c)) == 0) {
		printf(": illegal option --%c ", c);
		if (argv[optind][++sp] == '\0') {
			optind++;
			sp = 1;
		}
		return('?');
	}
	if (*++cp == ':') {
		if (argv[optind][sp + 1] != '\0')
			optarg = &argv[optind++][sp + 1];
		else if (++optind >= argc) {
			printf(": option requires an argument --%c ", c);
			sp = 1;
			return('?');
		}
		else
			optarg = argv[optind++];
		sp = 1;
	}else {
		if (argv[optind][++sp] == '\0') {
			sp = 1;
			optind++;
		}
		optarg = 0;
	}
	return(c);
}

int split_array(char* base, unsigned short vals[32]) {
	size_t pos = 0;
	char *token = strtok(base, ",");
	while (token != NULL) {
		vals[pos++] = atoi(token);
		token = strtok(NULL, ",");
	}
	return pos;
}

//创建配置实例
struct configure * configure_create(int argc, char * argv[]) {
    struct configure *cfg = (struct configure *)calloc(1, sizeof(configure_t));
	memset(cfg, 0x00, sizeof(configure_t));
#ifdef INNO_CLIENT
	strcpy(cfg->local_host, "0.0.0.0");
	strcpy(cfg->remote_host, "0.0.0.0");
	cfg->local_port = 8892;
	cfg->remote_port = 12443;
	cfg->app_type = 402;
	cfg->user_id = 829524397;
	strcpy(cfg->user_name, "8b0088ce-9b4d-402e-b506-436c95d368f1");
	strcpy(cfg->user_cipher, "9663a54e-cd4d-4720-9796-dc27775f41ac");
	int c = 0;
	char stritem[256] = { 0 };
	while ((c = getopt(argc, argv, "a:u:n:i:s:p:")) != -1) {
		switch (c) {
		case 'a':
			cfg->app_type = atoi(optarg);
			break;
		case 'u':
			cfg->user_id = atoll(optarg);
			break;
		case 'n':
			memset(cfg->user_name, 0x00, 32);
			strncpy(cfg->user_name, optarg, 32);
			break;
		case 'i':
			memset(cfg->user_cipher, 0x00, 32);
			strncpy(cfg->user_cipher, optarg, 32);
			break;
		case 's':
			memset(cfg->remote_host, 0x00, 32);
			strncpy(cfg->remote_host, optarg, 32);
			break;
		case 'p':
			cfg->remote_port = atoi(optarg);
			break;
		default:
			break;
		}
	}
#elif INNO_SERVER
	cfg->ports[0] = 12443;
	int c = 0;
	char stritem[256] = { 0 };
	while ((c = getopt(argc, argv, "v:p:")) != -1) {
		switch (c) {
		case 'v':
			fprintf(stderr, "version:%s","1.0.0.1");
			break;
		case 'p':
			memset(&stritem, 0x00, sizeof(stritem));
			strncpy(stritem, optarg, 256);
			split_array(stritem, cfg->ports);
			break;
		default:
			break;
		}
	}
#endif
    return cfg;
}

//销毁配置实例
void configure_destroy(struct configure *cfg) {
    if (cfg) {
        free(cfg);
    }
}

//Hex字符转整数
uint8_t char_to_int8(uint8_t ch) {
	if (ch >= '0' && ch <= '9')return (uint8_t)(ch - '0');
	if (ch >= 'a' && ch <= 'f')return (uint8_t)(ch - 'a' + 10);
	if (ch >= 'A' && ch <= 'F')return (uint8_t)(ch - 'A' + 10);
	return -1;
}

//16个字节UUID转成字符串类型 
void uuid_to_string(const uint8_t uuid[16], char * str){
	sprintf(str, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
		uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
}

//字符串类型的UUID转成16个字节数组
void string_to_uuid( char * data, uint8_t uuid[16] ) {
	char uuid_data[0x20] = { 0 };
	size_t uuid_pos = 0;
	for (size_t i = 0; i < strlen(data); i++) {
		if (data[i] != '-'  && uuid_pos <= 0x20) {
			uuid_data[uuid_pos++] = data[i];
		}
	}
	size_t sav_len = uuid_pos / 2;
	for ( size_t i = 0; i < sav_len; i++ ) {
		uint8_t hb = char_to_int8(uuid_data[i *2 ]);
		uint8_t hl  = char_to_int8(uuid_data[i *2 + 1]);
		uuid[i] = (hb << 4) | hl;
	}
}

//生成自定义session_id
void create_session_id(struct session_id * sid, uint8_t type, uint8_t * token) {
 #define _USE_32BIT_TIME_T
	memset(sid, 0x00, sizeof(struct session_id));
	sid->version[0] = '1';
	sid->version[1] = '0';
	sid->version[2] = '0';
	sid->version[3] = '4';
	sid->pkg_type = type;
	sid->timestamp = (uint32_t)time(NULL);
	memcpy(sid->token, token, 16);
	for (size_t i = 0; i < sizeof(sid->pandding); i++) {
		sid->pandding[i] = rand() % 0xFF;
	}
	uint8_t * data = (uint8_t*)sid;
	for (size_t i = 0; i < 31; i++) {
		sid->cs += data[i];
	}
}

//sessionID校检，查看是否为inno自建sessionID
bool check_session_id(uint8_t * sid) {
	uint8_t cs = 0;
	for (size_t i = 0; i < 31; i++) {
		cs += sid[i];
	}
	return (cs == sid[31]);
}
