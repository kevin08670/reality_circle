#ifndef __CONFIGURE_H__
#define __CONFIGURE_H__
#include <stdbool.h>
#include <stdint.h>

//�û���Ϣ�������32���ֽ���
#pragma pack(push, 1)
typedef struct auth_info {
	uint16_t app_type;
	uint64_t user_id;
	uint8_t user_name[16];
	uint8_t user_cipher[16];
}auth_info_t;
#pragma pack(pop)

//��32���ֽڣ�
#pragma pack(push, 1)
typedef struct session_id {
	uint8_t   pkg_type;                 //���ݰ�����
	uint8_t   version[4];
	uint32_t timestamp;
	uint8_t   token[16];                 //��֤����session�����ϴ�token,���ٷ�����֤��Ϣ(����������֤�ɴ棬�������token)
	uint8_t   pandding[6];
	uint8_t   cs;
}session_id_t;
#pragma pack(pop)

#define INNO_CLIENT

typedef struct configure{
#ifdef INNO_CLIENT
	char local_host[32];
	unsigned short local_port;
	char remote_host[32];
	unsigned short remote_port;
	unsigned short app_type;
	unsigned long long user_id;
	char user_name[40];
	char user_cipher[40];
	char conn_id[16];
	char fake_sni[256];
#elif INNO_SERVER
	unsigned short port;
#endif 
}configure_t;

struct configure* configure_create(int argc, char *  argv[]);
void configure_destroy(struct configure *info);

void uuid_to_string(const uint8_t uuid[16], char * str);
void string_to_uuid(char * data, uint8_t uuid[16]);

void create_session_id(struct session_id * sid, uint8_t type, uint8_t * token);
bool check_session_id(uint8_t * sid);

#endif //__CONFIGURE_H__
