#ifndef __INNO_TLS_H__
#define __INNO_TLS_H__
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
int parse_client_hello_sni(const uint8_t *data, size_t data_len, char* sni);
int parse_server_hello_tlsversion(const uint8_t *data, size_t data_len, uint16_t* version);
#endif // __INNO_TLS_H__