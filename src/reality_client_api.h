//
// Created by ssrlive on 4/6/18.
//

#ifndef REALITY_NATIVE_CLIENT_API_H
#define REALITY_NATIVE_CLIENT_API_H

#ifdef __cplusplus
extern "C" {
#endif

#include "configure.h"
#include <stdbool.h>

struct reality_client_state;

/* listener.c */
int reality_run_loop_begin(struct configure *cf, void(*feedback_state)(void *p, struct reality_client_state *state, const char* info), void *p);
void reality_run_loop_shutdown(struct reality_client_state *state);
 
#ifdef __cplusplus
}
#endif

#endif //REALITY_NATIVE_CLIENT_API_H
