#include "user_mgr.h"
#include <time.h>
#include <string.h>
#include <assert.h>
#include <c_stl_lib.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include "../text_in_color.h"

typedef struct usermgr {
	struct cstl_map *online_users;
	struct cstl_map *local_users;
}usermgr_t;

#pragma pack(push, 1)
typedef struct user_info {
	char  token[40];
	uint16_t app_type;
	uint64_t user_id;
	char user_name[16];
	char user_cipher[16];
	clock_t auth_time;
	uint32_t  last_heartbeat;
	uint32_t  user_mark;
}user_info_t;
#pragma pack(pop)

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

struct usermgr * usermgr_create() {
	struct usermgr *mgr = NULL;
	mgr = (struct usermgr *) calloc(1, sizeof(usermgr_t));
	mgr->online_users = cstl_map_new(compare_key, NULL, NULL);
	mgr->local_users = cstl_map_new(compare_key, NULL, NULL);
	//加载本地数据库,用于没有接入inno-auth模块时测试使用
	FILE* fp = fopen("./acc.txt", "r");
	if (NULL != fp) {
		char sline[512] = { 0 };
		while ( fgets(sline, 256, fp) != NULL ) {
			char acc_key[256] = { 0 };
			uint16_t app_type;
			uint64_t user_id;
			char str_name[40] = { 0 };
			char str_cipher[40] = { 0 };
			uint32_t user_mark = 0;
			if (5 == sscanf(sline, "%hu_%"PRIu64":%[^@]@%[^#]#%u[^\r|\n]", &app_type, &user_id, str_name, str_cipher, &user_mark)) {
				sprintf(acc_key, "%d_%"PRIu64":%s@%s", app_type, user_id, str_name, str_cipher);
				bool b_exit = true;
				cstl_map_insert(mgr->local_users, acc_key, strlen(acc_key)+1, &b_exit, sizeof(bool));
			}
		}
		fclose(fp);
		fp = NULL;
	}else {
		xtrace(text_color_red, "usermgr local acc.txt fail.");
	}
	//加载在线用户信息,客户端能通过session/token进行通信验证
	FILE* fp2 = fopen("./.cache", "r");
	if (NULL != fp2) {
		struct user_info user;
		while( fread(&user, sizeof(user_info_t), 1, fp2) ) {
			cstl_map_insert(mgr->online_users, user.token, strlen(user.token)+1, (void*)&user, sizeof(user_info_t));
			memset(&user, 0x00, sizeof(user_info_t));
		}
		fclose(fp2);
		fp2 = NULL;
	}
	return mgr;
}

bool usermgr_add_user(struct usermgr* mgr, const char* key, struct auth_info* auth) {
	if (cstl_map_is_key_exists(mgr->online_users, &key) == 0) {
		struct user_info info;
		memset(&info, 0x00, sizeof(user_info_t));
		info.user_id = auth->user_id;
		memcpy(info.token, key,strlen(key));
		memcpy(info.user_name, auth->user_name,16);
		memcpy(info.user_cipher, auth->user_cipher,16);
		info.auth_time = clock();
		info.last_heartbeat = clock();
		info.user_mark = rand();
		cstl_map_insert(mgr->online_users, key, strlen(key)+1, (void*)&info, sizeof(user_info_t));
		return true;
	}else {
		assert(!"the item have exist!");
	}
	return false;
}

void usermgr_remove_user(struct usermgr* mgr, const char* host) {
	if (mgr == NULL || host == NULL) {
		return;
	}
	if (cstl_map_is_key_exists(mgr->online_users, &host) != 0) {
		if (cstl_map_remove(mgr->online_users, &host) != CSTL_ERROR_SUCCESS) {
			assert(!"remove the item failed!");
		}
	}else {
		assert(!"the item not exist!");
	}
}

void user_remove_cb(struct cstl_map *map, const void *key, const void *value, int *stop, void *p) {
	struct user_cache *user_cache = (struct user_cache *)p;
	//struct user_timestamp **addr = (struct user_timestamp **)value;
	//if (addr && *addr) {
	//	if ((clock() - (*addr)->timestamp) > user_cache->expire_interval) {
	//		cstl_map_remove(map, key);
	//	}
	//}
	(void)stop;
}

bool usermgr_is_localuser_exist(struct usermgr *mgr, const char *key) {
	if (mgr && key && cstl_map_is_key_exists(mgr->local_users, key) != 0) {
		return true;
	}
	return false;
}

bool usermgr_is_online(struct usermgr *mgr, const char *key) {
	if (mgr && key && cstl_map_is_key_exists(mgr->online_users, key) != 0) {
		return true;
	}
	return false;
}

void usermgr_destroy(struct usermgr *mgr) {
	cstl_map_delete(mgr->local_users);
	cstl_map_delete(mgr->online_users);
	free(mgr);
}

//用户本地验证认证，只检查是否在local用户列表中(用于测试)
bool usermgr_local_auth(struct usermgr *mgr, const char * key) {
	return  cstl_map_is_key_exists(mgr->local_users, key);
}

//存储在线用户信
void usermgr_online_save(struct usermgr *mgr) {
	FILE* fp = fopen("./.cache", "w");
	if (NULL != fp) {
		struct cstl_iterator* it = cstl_map_new_iterator(mgr->online_users);
		const void* element;
		while ((element = it->next(it))) {
			const struct user_info* value = it->current_value(it);
			fwrite(value, sizeof(user_info_t), 1, fp);
		}
		cstl_map_delete_iterator(it);
		fclose(fp);
		fp = NULL;
	}
}

void print_online_user(struct usermgr *mgr) {
	struct cstl_iterator* it = cstl_map_new_iterator(mgr->online_users);
	const void* element;
	while ((element = it->next(it))) {
		const char * key = it->current_key(it);
		const struct user_info* user = it->current_value(it);
		char str_user_name[40] = { 0 };
		char str_user_cipher[40] = { 0 };
		uuid_to_string(user->user_name, str_user_name);
		uuid_to_string(user->user_cipher, str_user_cipher);
		xtrace(text_color_blue, "%s %"PRIu64"  %s %s", key, user->user_id, str_user_name, str_user_cipher);
	}
	cstl_map_delete_iterator(it);
}

void print_local_user(struct usermgr *mgr) {
	struct cstl_iterator* it = cstl_map_new_iterator(mgr->local_users);
	const void* element;
	while ((element = it->next(it))) {
		const char * key = it->current_key(it);
		xtrace(text_color_blue, "%s", key);
	}
	cstl_map_delete_iterator(it);
}