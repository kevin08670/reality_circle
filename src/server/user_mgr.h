#ifndef __USER_MANAGER_H__
#define __USER_MANAGER_H__

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include "../configure.h"

struct usermgr;
struct usermgr* usermgr_create();
bool usermgr_add_user(struct usermgr* mgr, const char* key, struct auth_info* auth);
void usermgr_remove_user(struct usermgr* mgr, const char* host);
bool usermgr_is_localuser_exist(struct usermgr*mgr, const char* key);
bool usermgr_is_online(struct usermgr* mgr, const char* key);
void usermgr_destroy(struct usermgr* mgr);
bool usermgr_local_auth(struct usermgr* mgr, const char* key);
void usermgr_online_save(struct usermgr* mgr);
void print_online_user(struct usermgr* mgr);
void print_local_user(struct usermgr* mgr);

#endif // __USER_MANAGER_H__