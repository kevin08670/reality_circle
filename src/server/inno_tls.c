#include "inno_tls.h"
#include <string.h>
/**
 * 解析 TLS Client Hello 以獲取 SNI
 * @param data: 指向 TLS 數據包起始位置的指針
 * @param data_len: 數據長度
 * @return: 成功返回 0，失敗返回 -1
 */
int parse_client_hello_sni(const uint8_t *data, size_t data_len, char* sni) {
	size_t pos = 0;
	// 1. 檢查 TLS Record Layer (至少 5 字節)
	if (data_len < 5 || data[0] != 0x16) return -1; // 0x16 = Handshake
	pos += 5;
	// 2. 檢查 Handshake Type (至少 4 字節)
	if (pos + 4 > data_len || data[pos] != 0x01) return -1; // 0x01 = Client Hello
	pos += 4;
	// 3. 跳過 Client Version (2) + Random (32)
	pos += 34;
	// 4. 跳過 Session ID (1 + len)
	if (pos + 1 > data_len) return -1;
	pos += 1 + data[pos];
	// 5. 跳過 Cipher Suites (2 + len)
	if (pos + 2 > data_len) return -1;
	uint16_t cipher_len = (data[pos] << 8) | data[pos + 1];
	pos += 2 + cipher_len;
	// 6. 跳過 Compression Methods (1 + len)
	if (pos + 1 > data_len) return -1;
	pos += 1 + data[pos];
	// 7. 進入 Extensions (2 + len)
	if (pos + 2 > data_len) return -1;
	uint16_t extensions_len = (data[pos] << 8) | data[pos + 1];
	pos += 2;
	size_t extensions_end = pos + extensions_len;
	// 8. 遍歷所有 Extension 尋找 SNI (Type 0x0000)
	while (pos + 4 <= extensions_end && pos + 4 <= data_len) {
		uint16_t ext_type = (data[pos] << 8) | data[pos + 1];
		uint16_t ext_len = (data[pos + 2] << 8) | data[pos + 3];
		pos += 4;
		if (ext_type == 0x0000) { // SNI 擴展
			if (pos + ext_len > data_len) return -1;
			// SNI 結構: List Len(2) + Type(1) + Name Len(2) + Name
			size_t sni_pos = pos + 2; // 跳過 List Length
			if (sni_pos + 3 > data_len) return -1;
			uint8_t name_type = data[sni_pos];
			uint16_t name_len = (data[sni_pos + 1] << 8) | data[sni_pos + 2];
			sni_pos += 3;
			if (name_type == 0x00 && sni_pos + name_len <= data_len) {
				memcpy(sni, &data[sni_pos], name_len);
				return 0;
			}
		}
		pos += ext_len;
	}
	return -1;
}

/**
 * 解析 TLS Client Hello 以獲取 SNI
 * @param data: 指向 TLS 數據包起始位置的指針
 * @param data_len: 數據長度
 * @return: 成功返回 0，失敗返回 -1
 */
int parse_server_hello_tlsversion(const uint8_t *data, size_t data_len, uint16_t* version) {
	size_t pos = 0;
	// 1. 檢查 TLS Record Layer (至少 5 字節)
	if (data_len < 5 || data[0] != 0x16) return -1; // 0x16 = Handshake
	pos += 5;
	// 2. 檢查 Handshake Type (至少 4 字節)
	if (pos + 4 > data_len || data[pos] != 0x02) return -1; // 0x01 = Client Hello
	pos += 4;
	// 3. 跳過 Client Version (2) + Random (32)
	pos += 34;
	// 4. 跳過 Session ID (1 + len)
	if (pos + 1 > data_len) return -1;
	pos += 1 + data[pos];
	// 5. 跳過 Cipher Suites (2 + len)
	if (pos + 2 > data_len) return -1;
	pos += 2;
	// 6. 跳過 Compression Methods (1 + len)
	if (pos + 1 > data_len) return -1;
	pos += 1;
	// 7. 進入 Extensions (2 + len)
	if (pos + 2 > data_len) return -1;
	uint16_t extensions_len = (data[pos] << 8) | data[pos + 1];
	pos += 2;
	size_t extensions_end = pos + extensions_len;
	// 8. 遍歷所有 Extension 尋找 SNI (Type 0x0000)
	while (pos + 4 <= extensions_end && pos + 4 <= data_len) {
		uint16_t ext_type = (data[pos] << 8) | data[pos + 1];
		uint16_t ext_len = (data[pos + 2] << 8) | data[pos + 3];
		pos += 4;
		if (ext_type == 0x002b) {
			if (pos + ext_len > data_len) return -1;
			*version = (data[pos] << 8) + data[pos + 1];
			return 0;
		}
		pos += ext_len;
	}
	return -1;
}

