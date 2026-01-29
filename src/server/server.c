// xProxy.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>
#include <uv.h>
#include <c_stl_lib.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>
#include <mbedtls/ssl_ticket.h>
#include <mbedtls/ssl_cache.h>
#include <mbedtls/platform.h>
#ifdef WIN32
#include <process.h>
#else 
#define min(a,b) (((a) < (b)) ? (a) : (b))
#endif
#include "../s5.h"
#include "../sockaddr_universal.h"
#include "../text_in_color.h"
#include "../configure.h"
#include "../mycert.h"
#include "inno_tls.h"
#include "addr_mgr.h"
#include "user_mgr.h"
#include "cert_mgr.h"

// ============ 性能优化配置 ============
#define FRAME_SIZE                          16384            // 优化: 从65535减少到16KB，更适合TLS记录大小(16KB限制)
#define BUFFER_POOL_SIZE               32                 // 缓冲池大小
#define INITIAL_BUFFER_CAPACITY   32768           // 初始缓冲区容量 32KB
#define MAX_BUFFER_CAPACITY       (1024*1024)  // 最大缓冲区容量 1MB

// ============ 简单内存池实现 ============
typedef struct buffer_pool_item {
    char *buffer;
    size_t capacity;
    int in_use;
} buffer_pool_item_t;

static buffer_pool_item_t g_buffer_pool[BUFFER_POOL_SIZE];

// 初始化缓冲池
static void buffer_pool_init(void) {
    for (int i = 0; i < BUFFER_POOL_SIZE; i++) {
        g_buffer_pool[i].buffer = (char *)malloc(FRAME_SIZE);
        g_buffer_pool[i].capacity = FRAME_SIZE;
        g_buffer_pool[i].in_use = 0;
    }
}

// 从池中获取缓冲区
static char* buffer_pool_get(size_t *out_capacity) {
    for (int i = 0; i < BUFFER_POOL_SIZE; i++) {
        if (!g_buffer_pool[i].in_use && g_buffer_pool[i].buffer) {
            g_buffer_pool[i].in_use = 1;
            if (out_capacity) *out_capacity = g_buffer_pool[i].capacity;
            return g_buffer_pool[i].buffer;
        }
    }
    // 池已满，回退到普通 malloc
    char *buf = (char *)malloc(FRAME_SIZE);
    if (out_capacity) *out_capacity = FRAME_SIZE;
    return buf;
}

// 归还缓冲区到池
static void buffer_pool_release(char *buffer) {
    if (!buffer) return;
    for (int i = 0; i < BUFFER_POOL_SIZE; i++) {
        if (g_buffer_pool[i].buffer == buffer) {
            g_buffer_pool[i].in_use = 0;
            return;
        }
    }
    // 不是池中的缓冲区，直接释放
    free(buffer);
}

// 销毁缓冲池
// 优化: 添加安全检查，防止在异步操作仍在使用缓冲区时崩溃
static void buffer_pool_destroy(void) {
    for (int i = 0; i < BUFFER_POOL_SIZE; i++) {
        if (g_buffer_pool[i].buffer != NULL) {
            free(g_buffer_pool[i].buffer);
            g_buffer_pool[i].buffer = NULL;
        }
        g_buffer_pool[i].in_use = 0;
        g_buffer_pool[i].capacity = 0;
    }
}

/* Session states. */
#define TUNNEL_STAGE_MAP(V)   \
    V( 0, tunnel_stage_tls_clientHello, "tunnel_stage_tls_clientHello")  \
	V( 1, tunnel_stage_tls_stealhandle, "tunnel_stage_tls_stealhandle")  \
	V( 2, tunnel_stage_tls_handshake, "tunnel_stage_tls_handshake")  \
    V( 3, tunnel_stage_tls_handshaked,  "tunnel_stage_tls_handshaked")   \
    V( 4, tunnel_stage_tls_streaming, "tunnel_stage_tls_streaming")  \
    V( 5, tunnel_stage_probe_streaming, "tunnel_stage_probe_streaming")  \
    V( 6, tunnel_stage_shutdown, "tunnel_stage_shutdown")  \

enum tunnel_stage {
#define TUNNEL_STAGE_GEN(code, name, _) name = code,
	TUNNEL_STAGE_MAP(TUNNEL_STAGE_GEN)
#undef TUNNEL_STAGE_GEN
	tunnel_stage_max,
};

static const char * tunnel_stage_string(enum tunnel_stage stage) {
#define TUNNEL_STAGE_GEN(_, name, name_str) case name: return name_str;
	switch (stage) {
		TUNNEL_STAGE_MAP(TUNNEL_STAGE_GEN)
	default:
		return "Unknown stage.";
	}
#undef TUNNEL_STAGE_GEN
}

//TCP connect context 
typedef struct socket_ctx {
	uv_handle_t * handle;
	uv_timer_t timer_handle;
	struct uv_buf_t buf;
	size_t buf_len;
}socket_ctx_t;

// 隧道连接上下文 (核心结构体，保存隧道状态)
typedef struct conn_context {
	enum tunnel_stage stage;
	uv_tcp_t * input_handle;
	char *input_read_buffer;                           //输入层
	size_t input_read_buffer_len;
	size_t input_read_buffer_offset;
	size_t input_read_buffer_capacity;                //优化: 预分配容量，减少 realloc 次数
	uv_handle_t * output_handle;                   //输出 / 转发层(TCP/UDP用其一)
	char *output_read_buffer;
	size_t output_read_buffer_len;
	size_t output_read_buffer_offset;
	size_t output_read_buffer_capacity;               //优化: 预分配容量，减少 realloc 次数
	unsigned char *ssl_read_buffer;                    //优化: TLS解密数据复用缓冲区
	size_t ssl_read_buffer_capacity;                  //优化: TLS解密缓冲区容量
	size_t flow_read_len;
	uv_tcp_t * steal_handle;                           //窃取/回落层
	mbedtls_ssl_context ssl_ctx;
	mbedtls_ssl_config conf;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	union sockaddr_universal target_addr;
	uint16_t tls_version;
	char probe_sni[256];
	struct sockaddr_in udp_dest;
	unsigned char session_id[32];
	bool is_handle_tlsintls;               //是否启用 TLS-in-TLS 转发 (直接转发 TLS 记录)
	bool is_probe;
	bool is_verified;
	bool is_uot;
} conn_context_t;

//函数定义
static void tunnel_dispatcher(conn_context_t* tunnel, socket_ctx_t* socket);
void do_inbround_handshake(conn_context_t* tunnel);
void do_inbround_intent_handle(conn_context_t* tunnel);
void do_stage_forword(conn_context_t* tunnel, socket_ctx_t* socket);
void do_stage_shutdown(conn_context_t* tunnel);
void do_steal_handle(conn_context_t* tunnel);
void on_steal_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
void on_steal_listen_cb(uv_connect_t *req, int status);
void on_steal_close_cb(uv_handle_t *handle);
void on_outbround_tcp_listen_cb(uv_connect_t *req, int status);
void on_outbround_close_cb(uv_handle_t *handle);
void on_outbround_udp_send_cb(uv_udp_send_t* req, int status);
void on_outbround_udp_recv(uv_udp_t* handle, ssize_t nread, const uv_buf_t* rcvbuf, const struct sockaddr* addr, unsigned flags);
int on_inbround_sni_callback(void *p_info, mbedtls_ssl_context *ssl, const unsigned char *name, size_t name_len);
int update_tunnel_tls_configure(conn_context_t* tunnel);

//成员定义
static unsigned int conn_channel_count = 0;
static struct ip_addr_cache * resolved_ip_cache = NULL;
static struct usermgr * my_usermgr = NULL;
static struct certmgr * my_certmgr = NULL;
struct cstl_map * my_tunnels = NULL;
struct configure * my_config = NULL;
static uv_tty_t tty_stdin;
static uv_signal_t signal_handle;

static int compare_tunnel(const void *left, const void *right) {
	void *pL = *(void **)left;
	void *pR = *(void **)right;
	if (pL == pR) return 0;
	return ((uintptr_t)pL < (uintptr_t)pR) ? -1 : 1;
}

/**
* 检查通道是否存在
*/
bool check_tunnel_exists(void * tunnel) {
	if (tunnel && cstl_map_is_key_exists(my_tunnels, &tunnel) != 0) {
		return true;
	}
	return false;
}

/**
* socket 写入完成回调
*/
static void uv_socket_write_done_cb(uv_write_t* req, int status) {
	if( status != 0 ){
		xtrace(text_color_white,"uv_socket_write_done_cb  ret:%d", status);
	}
	if (req->data) {
		free(req->data);
	}
	free(req);
}

/**
* TCP 写入数据到指定 socket
* 优化: 使用 malloc 代替 calloc (不需要清零)
* 优化: 对于小数据包，先尝试 uv_try_write，减少异步开销
*/
int socket_tcp_write(uv_stream_t* stream, const void* data, size_t len) {
	if (!stream  || !data || len == 0) return -1;
	// 优化: 对于小数据包（<4KB），先尝试同步写入，避免异步开销
	// uv_try_write 只在非阻塞模式下有效，且不会阻塞
	if (len <= 4096) {
		uv_buf_t try_buf = uv_buf_init((char*)data, len);
		ssize_t written = uv_try_write(stream, &try_buf, 1);
		if (written == (ssize_t)len) {    // 完全写入成功，直接返回
			return written;
		}
	}
	// 异步写入路径
	uv_write_t* req = (uv_write_t*)malloc(sizeof(uv_write_t));
	if (!req) return -1;
	char *write_buf = (char*)malloc(len);
	if (!write_buf) {
		free(req);
		return -1;
	}
	memcpy(write_buf, data, len);
	req->data = write_buf;
	uv_buf_t buf = uv_buf_init(write_buf, len);
	int ret = uv_write(req, stream, &buf, 1, uv_socket_write_done_cb);
	if (ret != 0) {
		xtrace(text_color_white,"socket_tcp_write  ret:%d", ret);
		free(write_buf);
		free(req);
		return ret;
	}
	return len;
}

/**
* UCP 写入数据到指定 socket
* 优化: 使用 malloc 代替 calloc (不需要清零)
* 优化: 对于小数据包，先尝试 uv_udp_try_send，减少异步开销
*/
int socket_udp_write(uv_udp_t* handle, const struct sockaddr* addr, const void* data, size_t len) {
	if (!handle || !data || len == 0) return -1;
	// 优化: 对于小 UDP 包，先尝试 uv_udp_try_send
	uv_buf_t try_buf = uv_buf_init((char*)data, len);
	int try_ret = uv_udp_try_send(handle, &try_buf, 1, addr);
	// 完全发送成功，直接返回
	if (try_ret == (int)len) {
		htrace(text_color_green, "socket_udp_write (try_send)", data, len);
		return len;
	}
	// 需要异步发送
	uv_udp_send_t * send_req = (uv_udp_send_t*)malloc(sizeof(uv_udp_send_t));
	if (!send_req) return -1;
	char *send_data = (char*)malloc(len);
	if (!send_data) {
		free(send_req);
		return -1;
	}
	memcpy(send_data, data, len);
	send_req->data = send_data;
	uv_buf_t  send_buf = uv_buf_init(send_data, len);
	htrace(text_color_green, "socket_udp_write", send_data, len);
	int ret = uv_udp_send(send_req, handle, &send_buf, 1, addr, on_outbround_udp_send_cb);
	if (ret != 0) {
		xtrace(text_color_white, "socket_udp_write ret:%d", ret);
		free(send_data);
		free(send_req);
		return ret;
	}
	return len;
}

/**
* 缓冲区分配回调 (libuv 读操作前调用)
* 优化: 使用内存池减少频繁的 malloc/free
* 优化: 考虑 suggested_size，但使用内存池大小以确保一致性
*/
void alloc_buffer_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
	size_t capacity = 0;
	buf->base = buffer_pool_get(&capacity);
	// 优化: 使用实际容量，但不超过建议大小（如果建议大小更小）
	// libuv 的 suggested_size 通常基于系统特性，但我们的池大小已经优化
	buf->len = (buf->base) ? (unsigned int)capacity : 0;
	(void)handle;
	// 注意: suggested_size 可能小于 FRAME_SIZE，但使用固定大小可以简化内存管理
}

/**
* 释放客户端 (TLS) 连接资源回调
*/
void on_inbround_close_cb(uv_handle_t *handle) {
	conn_context_t *conn_ctx = (conn_context_t *)handle->data;
	if ( !conn_ctx ) {
		xtrace(text_color_red, "on_inbround_close_cb context is null");
		return;
	}
	xtrace(text_color_white, "on_inbround_close_cb input:%p", conn_ctx->input_handle);
	if (conn_ctx->input_read_buffer) {
		free(conn_ctx->input_read_buffer);
		conn_ctx->input_read_buffer = NULL;
	}
	free(conn_ctx->input_handle);
	conn_ctx->input_handle = NULL;
	conn_ctx->stage = tunnel_stage_shutdown;
	tunnel_dispatcher(conn_ctx, NULL);
}

/**
* mbedTLS 的发送回调函数，将数据写入 libuv 流
* 优化: 使用 malloc 代替 calloc
* 优化: 对于小数据包，先尝试 uv_try_write
*/
int my_mbedtls_send(void *ctx, const unsigned char *buf, size_t len) {
	htrace(text_color_white, "my_mbedtls_send to client", (char*)buf, len);
	conn_context_t *conn_ctx = (conn_context_t *)ctx;
	if ( conn_ctx->input_handle ) {
		return socket_tcp_write((uv_stream_t*)conn_ctx->input_handle, buf, len);
	}
	return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

/**
* mbedTLS 的接收回调函数，从我们自己的缓存中读取数据
* 优化: 保留预分配的缓冲区容量，只重置长度和偏移量
*/
int my_mbedtls_recv(void *ctx, unsigned char *buf, size_t len) {
	conn_context_t *conn_ctx = (conn_context_t *)ctx;
	size_t available_data = conn_ctx->input_read_buffer_len - conn_ctx->input_read_buffer_offset;
	if (available_data == 0) {
		// 关键点: 没有数据可用，返回 WANT_READ 告诉 mbedTLS 等待,这样 mbedtls 就不会阻塞，而是依赖 libuv 的异步读事件
		return MBEDTLS_ERR_SSL_WANT_READ;
	}
	// 确定本次要读取的字节数，从缓存中拷贝数据到 mbedTLS 提供的缓冲区，更新偏移量
	size_t bytes_to_read = (len < available_data) ? len : available_data;
	memcpy(buf, conn_ctx->input_read_buffer + conn_ctx->input_read_buffer_offset, bytes_to_read);
	conn_ctx->input_read_buffer_offset += bytes_to_read;
	// 优化: 如果所有缓存的数据都已消费，只重置长度和偏移量，保留容量
	if (conn_ctx->input_read_buffer_offset == conn_ctx->input_read_buffer_len) {
		conn_ctx->input_read_buffer_len = 0;
		conn_ctx->input_read_buffer_offset = 0;
	}
	return (int)bytes_to_read;
}

/**
* mbedTLS 接收超时回调 
* (在 libuv 模型中，此函数和 my_mbedtls_recv 效果相同)
*/
int my_mbedtls_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout) {
	(void)timeout;
	return  my_mbedtls_recv(ctx, buf, len);
}

/**
* 将ssl缓存数据全部发送完成
*/
int application_data_forword(void *ctx, const unsigned char *buf, size_t len) {
	conn_context_t *conn_ctx = (conn_context_t *)ctx;
	int ret = 0;
	size_t sent = 0;
	do {
		ret = mbedtls_ssl_write(&conn_ctx->ssl_ctx, buf + sent, len - sent);
		if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
			continue;
		}else if (ret < 0) {
			xtrace(text_color_white, "application_data_forword ret:%d", ret);
			break;
		}
		sent += ret;
	} while (sent < len);
	return ret;
}

/**
* 读取探测服务器返回数据
* 该阶段已进入tunnel_stage_origin_streaming状态，直接透明转发.
*/
void on_probe_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
	conn_context_t *conn_ctx = (conn_context_t *)stream->data;
	if ( conn_ctx && conn_ctx->output_handle && nread > 0) {
		socket_ctx_t  ctx;
		ctx.buf = *buf;
		ctx.buf_len = nread;
		ctx.handle = conn_ctx->output_handle;
		htrace(text_color_white, "on_probe_read_cb form target", buf->base, nread);
		tunnel_dispatcher(conn_ctx, &ctx);
	}else {
		xtrace(text_color_white, "on_probe_read_cb to close: %s", uv_strerror(nread));
		uv_close((uv_handle_t*)stream, on_outbround_close_cb);
	}
	if (buf && buf->base) buffer_pool_release(buf->base); 
}

/**
* 监听探测服务器
* 待连接成功后，直接将clientHello数据包发送至探测服务器
*/
void on_probe_listen_cb(uv_connect_t *req, int status) {
	conn_context_t * tunnel = (conn_context_t *)req->data;
	if (status < 0 || !tunnel) {
		xtrace(text_color_white, "on_probe_listen_cb  error: %s", uv_strerror(status));
		if (tunnel && tunnel->output_handle) {
			uv_close((uv_handle_t*)tunnel->output_handle, on_outbround_close_cb);
		}
		goto exit;
	}
	xtrace(text_color_white, "on_probe_listen_cb read start and write CH to target.");
	uv_read_start((uv_stream_t *)tunnel->output_handle, alloc_buffer_cb, on_probe_read_cb);
	size_t  data_len = tunnel->ssl_ctx.private_in_msglen + 5;
	uv_write_t *write_req = (uv_write_t *)malloc(sizeof(uv_write_t));
	if (!write_req) {
		goto exit;
	}
	char *write_data = (char*)malloc(data_len);
	if (!write_data) {
		free(write_req);
		goto exit;
	}
	memcpy(write_data, tunnel->ssl_ctx.private_in_hdr, data_len);
	write_req->data = write_data;
	uv_buf_t write_buf = uv_buf_init(write_data, (unsigned int)data_len);
	htrace(text_color_white, "on_probe_listen_cb uv_write to target", tunnel->ssl_ctx.private_in_hdr, data_len);
	int ret = uv_write(write_req, (uv_stream_t*)tunnel->output_handle, &write_buf, 1, uv_socket_write_done_cb);
	if( ret != 0 ) {
		xtrace(text_color_white, "on_probe_listen_cb ret:%d", ret);
		free(write_data);
		free(write_req);
		goto exit;
	}
	tunnel->stage = tunnel_stage_probe_streaming;
exit:
	free(req);
}

/**
* 探测域名解析回调
* 成功返回将直接连接探测服务器
*/
static void get_probe_addrinfo_done_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs) {
	conn_context_t *tunnel = (conn_context_t *)req->data;
	if (status==0 && tunnel && addrs && check_tunnel_exists(tunnel)) {
		struct sockaddr_in dest = *(const struct sockaddr_in*)addrs->ai_addr;
		dest.sin_port = htons(tunnel->target_addr.addr4.sin_port);
		char * domain = (char*)req->reserved[0];
		if (ip_addr_cache_is_address_exist(resolved_ip_cache, domain) == false) {
			union sockaddr_universal * address = (union sockaddr_universal*) malloc(sizeof(union sockaddr_universal));
			address->addr4.sin_addr = dest.sin_addr;
			address->addr4.sin_port = dest.sin_port;
			ip_addr_cache_add_address(resolved_ip_cache, domain, address);
		}
		//连接到目标服务器
		xtrace(text_color_white, "get_probe_addrinfo_done_cb push cache domain:%s ip:%s:%d", domain, inet_ntoa(dest.sin_addr), tunnel->target_addr.addr4.sin_port);
		tunnel->output_handle = (uv_handle_t*)malloc(sizeof(uv_tcp_t));
		uv_tcp_init(uv_default_loop(), (uv_tcp_t*)tunnel->output_handle);
		tunnel->output_handle->data = (void*)tunnel;
		uv_connect_t *conn_req = (uv_connect_t *)malloc(sizeof(uv_connect_t));
		if (!conn_req) {
			uv_close((uv_handle_t*)tunnel->output_handle, on_outbround_close_cb);
			goto exit;
		}
		conn_req->data = (void*)tunnel;
		int ret = uv_tcp_connect(conn_req, (uv_tcp_t*)tunnel->output_handle, (const struct sockaddr *)&dest, on_probe_listen_cb);
		if( ret != 0 ) {
			xtrace(text_color_white, "get_probe_addrinfo_done_cb uv_tcp_connect ret:%d", ret);
			uv_close((uv_handle_t*)tunnel->output_handle, on_outbround_close_cb);
			free(conn_req);
		}
	}
	else if (tunnel && check_tunnel_exists(tunnel)) {
		tunnel->stage = tunnel_stage_shutdown;
		tunnel_dispatcher(tunnel, NULL);
	}
exit:
	if(addrs)uv_freeaddrinfo(addrs);
	free(req->reserved[0]);
	free(req);
}

/**
* 连接探测目标服务器
* 针对非INNO请求，响应防火墙探测行为，直接连接SNI对应的服务器
* 1. 检查域名在地址解析缓存中是否已有相应的解析，有否进行TCP连接
* 2. 需要进行域名解析，待回调后进行连接。
*/
void do_probe_connect(conn_context_t* tunnel, socket_ctx_t* ctx) {
	//如果不是inno session id,  将client 直接到到目标服务器
	const char * domainname = mbedtls_ssl_get_client_sni(&tunnel->ssl_ctx);
	tunnel->target_addr.addr4.sin_port = 443;
	if ( !domainname || strlen(domainname) < 1) {
		tunnel->stage = tunnel_stage_shutdown;
		tunnel_dispatcher(tunnel, NULL);
		return;
	}
	//如果域名在已在缓存中存在
	union sockaddr_universal * query_addr = ip_addr_cache_retrieve_address(resolved_ip_cache, domainname, &malloc);
	if (query_addr) {
		struct sockaddr_in dest;
		dest.sin_family = AF_INET;
		dest.sin_port = htons(tunnel->target_addr.addr4.sin_port);
		dest.sin_addr = query_addr->addr4.sin_addr;
		tunnel->output_handle = (uv_handle_t*)malloc(sizeof(uv_tcp_t));
		uv_tcp_init(uv_default_loop(), (uv_tcp_t*)tunnel->output_handle);
		tunnel->output_handle->data = (void*)tunnel;
		uv_connect_t *conn_req = (uv_connect_t *)malloc(sizeof(uv_connect_t));
		memset(conn_req, 0x00, sizeof(uv_connect_t));
		conn_req->data = tunnel;
		int ret =uv_tcp_connect(conn_req, (uv_tcp_t*)tunnel->output_handle, (const struct sockaddr *)&dest, on_probe_listen_cb);
		if( ret != 0 ) {
			xtrace(text_color_white, "do_tls_target_request uv_tcp_connect ret:%d", ret);
			uv_close((uv_handle_t*)tunnel->output_handle, on_outbround_close_cb);
			free(conn_req);
		}
		xtrace(text_color_white, "do_tls_target_request pull cache domain:%s ip:%s:%d", domainname, inet_ntoa(dest.sin_addr), tunnel->target_addr.addr4.sin_port);
		free(query_addr);
		return;
	}
	//域名不在缓存列表中，进行dns域名请求
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	size_t domain_length = strlen(domainname) + 1;
	uv_getaddrinfo_t *query_req = (uv_getaddrinfo_t *)calloc(1, sizeof(*query_req));
	query_req->reserved[0] = (void*)malloc(domain_length);
	memset(query_req->reserved[0], 0x00, domain_length);
	strcpy(query_req->reserved[0], domainname);
	query_req->data = tunnel;
	xtrace(text_color_white, "uv_getaddrinfo_t domain:%s", query_req->reserved[0]);
	int ret = uv_getaddrinfo(uv_default_loop(), query_req, get_probe_addrinfo_done_cb, domainname, NULL, &hints);
	if (ret != 0) {
		tunnel->stage = tunnel_stage_shutdown;
		tunnel_dispatcher(tunnel, NULL);
		free(query_req->reserved[0]);
		free(query_req);
		query_req = NULL;
	}
}

/**
* 原始数据转发
* 针对非INNO请求，响应防火墙探测行为，直接转发SNI所对应的服务器数据
*/
void do_probe_forword(conn_context_t* tunnel, socket_ctx_t* socket) {
	char * data = socket->buf.base;
	size_t  size = (size_t)socket->buf_len;
#ifdef WIN32                                                                                                                          
	if (tunnel->input_handle && tunnel->output_handle && ((uv_tcp_t*)socket->handle)->socket == tunnel->input_handle->socket) {
#else
	if (tunnel->input_handle && tunnel->output_handle &&  socket->handle->u.fd == tunnel->input_handle->u.fd) {
#endif
		socket_tcp_write((uv_stream_t*)tunnel->output_handle, data, size);
		return;
	}
#ifdef WIN32
	if (tunnel->output_handle && ((uv_tcp_t*)socket->handle)->socket == ((uv_tcp_t*)tunnel->output_handle)->socket) {
#else
	if (tunnel->output_handle && socket->handle->u.fd == tunnel->output_handle->u.fd) {
#endif 
		application_data_forword(tunnel, data,size);
		return;
	}
	xtrace(text_color_white, "do_probe_forword handless size:%zu", size);
}

/**
* 域名解析回调
* 解析完成后将进入连接目标服务器状态
*/
static void getaddrinfo_done_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs) {
	conn_context_t *tunnel = (conn_context_t *)req->data;
	if ( status == 0 && tunnel && addrs  && check_tunnel_exists(tunnel) ) {
		char * domain = (char*)req->reserved[0];
		xtrace(text_color_white, "getaddrinfo_done_cb  conn: %p", tunnel);
		struct sockaddr_in dest = *(const struct sockaddr_in*)addrs->ai_addr;
		dest.sin_port = htons(/*tunnel->target_addr.addr4.sin_port*/ 443);
		if (!ip_addr_cache_is_address_exist(resolved_ip_cache, domain)) {
			xtrace(text_color_white, "getaddrinfo_done_cb push cache domain:%s ip:%s:%d", domain, inet_ntoa(dest.sin_addr), tunnel->target_addr.addr4.sin_port);
			union sockaddr_universal * address = (union sockaddr_universal*) malloc(sizeof(union sockaddr_universal));
			address->addr4.sin_addr = dest.sin_addr;
			address->addr4.sin_port = dest.sin_port;
			ip_addr_cache_add_address(resolved_ip_cache, domain, address);
		}
		//连接到目标服务器
		tunnel->output_handle = (uv_handle_t*)malloc(sizeof(uv_tcp_t));
		if (!tunnel->output_handle) {
			goto exit;
		}
		uv_tcp_init(uv_default_loop(), (uv_tcp_t*)tunnel->output_handle);
		tunnel->output_handle->data = (void*)tunnel;
		uv_connect_t *conn_req = (uv_connect_t *)malloc(sizeof(uv_connect_t));
		if (!conn_req) {
			uv_close((uv_handle_t*)tunnel->output_handle, on_outbround_close_cb);
			goto exit;
		}
		conn_req->data = (void*)tunnel;
		int ret = uv_tcp_connect(conn_req, (uv_tcp_t*)tunnel->output_handle, (const struct sockaddr *)&dest, on_outbround_tcp_listen_cb);
		if( ret != 0 ) {
			xtrace(text_color_white, "getaddrinfo_done_cb uv_tcp_connect ret:%d", ret);
			uv_close((uv_handle_t*)tunnel->output_handle, on_outbround_close_cb);
			free(conn_req);
		}
	}
	else if (tunnel && check_tunnel_exists(tunnel)) {
		tunnel->stage = tunnel_stage_shutdown;
		tunnel_dispatcher(tunnel, NULL);
	}
exit:
	if(addrs)uv_freeaddrinfo(addrs);
	free(req->reserved[0]);
	free(req);
}

/**
* inbround 读数据回调函数
*/
void on_inbround_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
	conn_context_t *conn_ctx = (conn_context_t *)stream->data;
	if ( nread <= 0 ) {
		if ( stream ) {uv_close((uv_handle_t*)stream, on_inbround_close_cb);}
		if (buf->base) buffer_pool_release(buf->base);
		return;
	}
	//被识别为TLS后，ApplicationData 将不进行封装，直接转发
	//htrace("on_inbround_read_cb", buf->base, nread);
	if (conn_ctx->is_handle_tlsintls && nread >= 5 && buf->base[0] == 0x17 && buf->base[1] == 0x03){
		socket_ctx_t  ctx;
		ctx.buf = uv_buf_init(buf->base, nread);
		ctx.buf_len = nread;
		ctx.handle = (uv_handle_t*)conn_ctx->input_handle;
		xtrace(text_color_white, "on_inbround_read_cb transfor tls data read:%d", nread);
		tunnel_dispatcher(conn_ctx, &ctx);
		buffer_pool_release(buf->base);
		return;
	}

	//1. 缓存原始网络数据
	// 优化: 使用预分配容量减少 realloc 次数
	size_t new_buffer_len = conn_ctx->input_read_buffer_len + nread;
	if (new_buffer_len > conn_ctx->input_read_buffer_capacity) {
		// 容量不足，扩容 (按2倍增长，最少 INITIAL_BUFFER_CAPACITY)
		size_t new_capacity = conn_ctx->input_read_buffer_capacity;
		if (new_capacity == 0) new_capacity = INITIAL_BUFFER_CAPACITY;
		while (new_capacity < new_buffer_len && new_capacity < MAX_BUFFER_CAPACITY) {
			new_capacity *= 2;
		}
		if (new_capacity < new_buffer_len) new_capacity = new_buffer_len;
		
		char *new_buf = (char *)realloc(conn_ctx->input_read_buffer, new_capacity);
		if (!new_buf) {
			buffer_pool_release(buf->base);
			uv_close((uv_handle_t*)stream, on_inbround_close_cb);
			return;
		}
		conn_ctx->input_read_buffer = new_buf;
		conn_ctx->input_read_buffer_capacity = new_capacity;
	}
	memcpy(conn_ctx->input_read_buffer + conn_ctx->input_read_buffer_len, buf->base, nread);
	conn_ctx->input_read_buffer_len = new_buffer_len;
	buffer_pool_release(buf->base);

	htrace(text_color_white, "on_inbround_read_cb cache", conn_ctx->input_read_buffer, conn_ctx->input_read_buffer_len);
	//握手过程开始(在这里获取并检查SNI，尚窃取证书并进入steal 流程)
	if (conn_ctx->stage == tunnel_stage_tls_clientHello) {
		char sni[256] = { 0 };
		if( parse_client_hello_sni(conn_ctx->input_read_buffer, conn_ctx->input_read_buffer_len, sni ) != 0) {
			xtrace(text_color_white,"parse_client_hello_sni fail.");
		}
		//检查SNI,已有版本及证书信息，则更新MBETLS通道版本支持 ，否则进入steal状态
		if ( certmgr_query_version(my_certmgr, sni, &conn_ctx->tls_version) == 0 ){
			conn_ctx->stage = tunnel_stage_tls_handshake;
			update_tunnel_tls_configure(conn_ctx);
		}else {
			strncpy(conn_ctx->probe_sni, sni, min(strlen(sni), sizeof(conn_ctx->probe_sni)-1) );
			conn_ctx->probe_sni[sizeof(conn_ctx->probe_sni) - 1] = '\0';
			conn_ctx->stage = tunnel_stage_tls_stealhandle;
		}
		tunnel_dispatcher(conn_ctx, NULL);
		return;
	}
	//握手过程
	if (conn_ctx->stage == tunnel_stage_tls_handshake) {
		xtrace(text_color_white, "on_inbround_read_cb handshake");
		do_inbround_handshake(conn_ctx);
		return;
	}
	//握手完成,  接收客户端目标地址访问请求
	else if (conn_ctx->stage == tunnel_stage_tls_handshaked) {
		xtrace(text_color_white, "on_inbround_read_cb handshaked");
		do_inbround_intent_handle(conn_ctx);
		return;
	}
	//传输过程
	else if (conn_ctx->stage == tunnel_stage_tls_streaming) {
		// 优化: 复用 ssl_read_buffer，避免循环中重复分配
		if (!conn_ctx->ssl_read_buffer) {
			conn_ctx->ssl_read_buffer = (unsigned char*)malloc(FRAME_SIZE);
			conn_ctx->ssl_read_buffer_capacity = FRAME_SIZE;
		}
		int ret = 0;
		do {
			ret = mbedtls_ssl_read(&conn_ctx->ssl_ctx, conn_ctx->ssl_read_buffer, conn_ctx->ssl_read_buffer_capacity);
			if ( ret > 0 ) {
				htrace(text_color_white, "on_inbround_read_cb streaming", conn_ctx->ssl_read_buffer, ret);
				socket_ctx_t  ctx;
				ctx.buf = uv_buf_init((char*)conn_ctx->ssl_read_buffer, ret);
				ctx.buf_len = ret;
				ctx.handle =(uv_handle_t*)conn_ctx->input_handle;
				tunnel_dispatcher(conn_ctx, &ctx);
			}
		} while (ret > 0);
		return;
	}
}

/**
* 新连接回调函数
*/
void on_inbround_listen_cb(uv_stream_t *server, int status) {
	if (status < 0) {
		xtrace(text_color_white, "on_inbround_listen_cb connection error: %s\n", uv_strerror(status));
		return;
	}
	// 1. 创建并初始化客户端上下文
	conn_context_t *conn_ctx = (conn_context_t*)malloc(sizeof(conn_context_t));
	if (!conn_ctx) {
		xtrace(text_color_red, "on_inbround_listen_cb malloc conn_context failed");
		return;
	}
	memset(conn_ctx, 0, sizeof(conn_context_t));	
	cstl_map_insert(my_tunnels, &conn_ctx, sizeof(conn_ctx), NULL, 0);
	conn_ctx->input_handle = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
	if (!conn_ctx->input_handle) {
		xtrace(text_color_red, "on_inbround_listen_cb malloc input_handle failed");
		cstl_map_remove(my_tunnels, &conn_ctx);
		free(conn_ctx);
		return;
	}
	uv_tcp_init(server->loop, conn_ctx->input_handle);
	conn_ctx->input_handle->data = (void*)conn_ctx;
	conn_ctx->stage = tunnel_stage_tls_clientHello;
	conn_ctx->tls_version = 0x0303;
	conn_channel_count++;
	// 2. 接受连接
	if (uv_accept(server, (uv_stream_t *)conn_ctx->input_handle) != 0) {
		xtrace(text_color_white, "on_inbround_listen_cb uv_accept error");
		uv_close((uv_handle_t*)conn_ctx->input_handle, on_inbround_close_cb);
		return;
	}
	// 3. 初始化 mbedTLS 上下文
	mbedtls_ssl_init(&conn_ctx->ssl_ctx);
	conn_ctx->ssl_ctx.private_user_data.n = sizeof(void*);
	conn_ctx->ssl_ctx.private_user_data.p = (void*)conn_ctx;
	mbedtls_ssl_set_bio(&conn_ctx->ssl_ctx, conn_ctx, my_mbedtls_send, my_mbedtls_recv, my_mbedtls_recv_timeout);
	uv_read_start((uv_stream_t*)conn_ctx->input_handle, alloc_buffer_cb, on_inbround_read_cb);
	xtrace(text_color_white, "on_inbround_listen_cb Accepted new connection. tunnel:%p count:%d", conn_ctx, conn_channel_count);
}

/*
* 握手阶段处理
* 1. 判段sessionID是否为INNO自定义ID, 否则直接跟据clientHello的SNI进行透明转发
* 2. 如果SSL握手完成，检查sessionID是否为token;
*/ 
void do_inbround_handshake(conn_context_t* tunnel) {
	if (tunnel->ssl_ctx.private_state != MBEDTLS_SSL_HANDSHAKE_OVER) {
		int ret = mbedtls_ssl_handshake(&tunnel->ssl_ctx);
		if (ret == 0) {
			tunnel->stage = tunnel_stage_tls_handshaked;
			do_inbround_intent_handle(tunnel);
			return;
		}else if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE){
			return;
		}
		char error_buf[100];
		mbedtls_strerror(ret, error_buf, sizeof(error_buf));
		xtrace(text_color_white,"do_inbround_handshake mbedtls_ssl_handshake:-0x%x: %s", (unsigned int)-ret, error_buf);
		tunnel->stage = tunnel_stage_shutdown;
		tunnel_dispatcher(tunnel, NULL);
	}
}

/**
* 释放outbround连接资源
*/
void on_outbround_close_cb(uv_handle_t *handle) {
	conn_context_t *conn_ctx = (conn_context_t *)handle->data;
	if (!conn_ctx) {
		xtrace(text_color_red, "on_outbround_close_cb  context is null");
		return;
	}
	xtrace(text_color_white, "on_outbround_close_cb handle output handle:%p", conn_ctx->output_handle);
	// 优化: 缓冲区在 do_stage_shutdown 中统一释放，避免重复释放
	free(conn_ctx->output_handle);
	conn_ctx->output_handle = NULL;
	conn_ctx->stage = tunnel_stage_shutdown;
	tunnel_dispatcher(conn_ctx, NULL);
}

/**
 * 目标服务器返回信息
 */
void on_outbround_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
	conn_context_t *conn_ctx = (conn_context_t *)stream->data;
	if ( !conn_ctx || !stream) {
		xtrace(text_color_red, "on_outbround_read_cb context or stream is null");
		goto quitproc;
	}
	if ( nread < 0 ) {
		xtrace(text_color_white,"on_outbround_read_cb [%d] to close, %s", nread, uv_strerror(nread));
		uv_close((uv_handle_t*)stream, on_outbround_close_cb);
		goto quitproc;
	}
#ifdef TLSINTLS_HANDLE
	if (!conn_ctx->is_handle_tlsintls) {
		//识别为目标服务器的Server HelloDone 后将直接转发接下去的数据 
		//16 03 03 00 04 0e 00 00 00
		if (nread >= 9) {
			char * data = &buf->base[nread - 9];
			if (data[0] == 0x16 && data[5] == 0x0E) {
				xtrace(text_color_white,"server hello done, Identify as TLS packets and forward directly.");
				conn_ctx->is_handle_tlsintls = true;
			}
		}
		goto quitproc;
	}
#endif
	// 优化: 避免 uv_buf_t 结构体拷贝，直接使用指针
	socket_ctx_t  ctx;
	ctx.buf.base = buf->base;  // 直接赋值，避免结构体拷贝
	ctx.buf.len = buf->len;
	ctx.buf_len = nread;
	ctx.handle = conn_ctx->output_handle;
	htrace(text_color_blue, "on_outbround_read_cb", buf->base, nread);
	conn_ctx->flow_read_len += nread;
	tunnel_dispatcher(conn_ctx, &ctx);
quitproc:
	if ( buf && buf->base ) {
		buffer_pool_release(buf->base);
	}
}

/**
 * 连接到目标服务器
 */
void on_outbround_tcp_listen_cb(uv_connect_t *req, int status) {
	conn_context_t * tunnel = (conn_context_t *)req->data;
	if (check_tunnel_exists(tunnel) ) {
		if (status < 0) {
			xtrace(text_color_white, "on_outbround_tcp_listen_cb  conn fail: %s", uv_strerror(status));
			tunnel->stage = tunnel_stage_shutdown;
			tunnel_dispatcher(tunnel, NULL);
		}else {
			uv_read_start((uv_stream_t *)tunnel->output_handle, alloc_buffer_cb, on_outbround_read_cb);
			static char comfirm[] = "connect target is ok.";
			size_t rsp_len = sizeof(comfirm) + rand() % 0x80;
			char * rsp_data = (char*)malloc(rsp_len);
			if (rsp_data) {
				memcpy(rsp_data, comfirm, sizeof(comfirm));
				// 优化: 只清零填充部分
				if (rsp_len > sizeof(comfirm)) {
					memset(rsp_data + sizeof(comfirm), 0x00, rsp_len - sizeof(comfirm));
				}
				application_data_forword(tunnel, (const unsigned char *)rsp_data, rsp_len);
				xtrace(text_color_white, "on_outbround_tcp_listen_cb connect target success!");
				tunnel->stage = tunnel_stage_tls_streaming;
				free(rsp_data);
			}
		}
	}
	free(req);
}

/**
 * 处理目标地址解析请求
 * 优化: 复用 ssl_read_buffer，避免每次分配
 */
void do_inbround_intent_handle(conn_context_t* tunnel) {
	// 优化: 复用 ssl_read_buffer
	if (!tunnel->ssl_read_buffer) {
		tunnel->ssl_read_buffer = (unsigned char*)malloc(FRAME_SIZE);
		tunnel->ssl_read_buffer_capacity = FRAME_SIZE;
	}
	int mbedtls_ret = mbedtls_ssl_read(&tunnel->ssl_ctx, tunnel->ssl_read_buffer, tunnel->ssl_read_buffer_capacity);
	xtrace(text_color_white, "on_inbround_read_cb tunnel_stage_tls_handshaked ret:%s(%d)", uv_strerror(mbedtls_ret), mbedtls_ret);
	if (mbedtls_ret > 0) {
		//解析客户端S5数据
		size_t frag;
		size_t size;
		struct socks5_address tag_addr;
		memset(&tag_addr, 0x00, sizeof(struct socks5_address));
		const uint8_t * data = s5_parse_upd_package(tunnel->ssl_read_buffer, mbedtls_ret, &tag_addr, &frag, &size);;
		if (!data) {//TCP传输用
			socket_ctx_t  ctx;
			ctx.buf = uv_buf_init((char*)tunnel->ssl_read_buffer, mbedtls_ret);
			ctx.buf_len = mbedtls_ret;
			ctx.handle = (uv_handle_t*)tunnel->input_handle;
			htrace(text_color_white, "on_inbround_read_cb tcp indicate", tunnel->ssl_read_buffer, mbedtls_ret);
			tunnel_dispatcher(tunnel, &ctx);
			goto quitproc;
		}

		//以下是UOT部分
		//udp传输用(UDP通道创建 
		struct sockaddr_in addr_udp;
		tunnel->output_handle = (uv_handle_t*)malloc(sizeof(uv_udp_t));
		int ret1 = uv_udp_init(uv_default_loop(), (uv_udp_t*)tunnel->output_handle);
		if( ret1 != 0 ) {	
			xtrace(text_color_white, "on_inbround_read_cb uv_udp_init ret:%d", ret1);
			free(tunnel->output_handle);
			tunnel->output_handle = NULL;
			goto quitproc;
		}
		uv_ip4_addr("0.0.0.0", 0, &addr_udp);
		int ret2 = uv_udp_bind((uv_udp_t*)tunnel->output_handle, (const struct sockaddr*)&addr_udp, 0);
		if( ret2 != 0 ) {
			xtrace(text_color_white, "on_inbround_read_cb uv_udp_bind ret:%d", ret2);
			uv_close((uv_handle_t*)tunnel->output_handle, on_outbround_close_cb);
			goto quitproc;
		}
		tunnel->output_handle->data = (void*)tunnel;
		tunnel->is_uot = true;
		int ret3 = uv_udp_recv_start((uv_udp_t*)tunnel->output_handle, alloc_buffer_cb, on_outbround_udp_recv);
		if( ret3 != 0 ) {
			xtrace(text_color_white, "on_inbround_read_cb uv_udp_recv_start ret:%d", ret3);
			uv_close((uv_handle_t*)tunnel->output_handle, on_outbround_close_cb);
			goto quitproc;
		}
		htrace(text_color_white, "on_inbround_read_cb udp indicate", data, size);

		//地址转换
		char* tmp = socks5_address_to_string(&tag_addr, &malloc, false);
		if ( !tmp ) {
			xtrace(text_color_white, "on_inbround_read_cb socks5_address_to_string failed");
			uv_close((uv_handle_t*)tunnel->output_handle, on_outbround_close_cb);
			goto quitproc;
		}
		uv_ip4_addr(tmp, tag_addr.port, &tunnel->udp_dest);
		free(tmp);

		//如果是UDP数据，直接通过UDP转发
		tunnel->stage = tunnel_stage_tls_streaming;
		uv_udp_send_t * send_req = (uv_udp_send_t*)malloc(sizeof(uv_udp_send_t));
		if (!send_req) goto quitproc;
		char *send_data = (char*)malloc(size);
		if (!send_data) {
			free(send_req);
			goto quitproc;
		}
		memcpy(send_data, data, size);
		send_req->data = send_data;
		uv_buf_t  buf = uv_buf_init(send_data, size);
		int ret4 = uv_udp_send(send_req, (uv_udp_t*)tunnel->output_handle, &buf, 1, (const struct sockaddr*)&tunnel->udp_dest, on_outbround_udp_send_cb);
		if( ret4 != 0 ) {
			xtrace(text_color_white, "on_inbround_read_cb uv_udp_send ret:%d", ret4);
			free(send_data);
			free(send_req);
		}
	}
quitproc:
	return;
}

/**
* 连接目标服务器(这里将收到第一个包)
* 包括S5的目标地址请求
* 用户认证相关信息
*/
void do_inbround_target_request(conn_context_t* tunnel, socket_ctx_t* socket) {
	if ( !tunnel || !socket) {
		return;
	}
	//区分UDP/TCP 数据请求
	if ( tunnel->is_uot  ) {
		size_t frag;
		size_t size;
		struct socks5_address addr;
		const uint8_t * data = s5_parse_upd_package(socket->buf.base, socket->buf_len, &addr, &frag, &size);
		if(!data){
			tunnel->stage = tunnel_stage_shutdown;
			tunnel_dispatcher(tunnel, socket);	
			return;
		}
		htrace(text_color_white, "udp recv", data, size);
		uv_udp_recv_start((uv_udp_t *)tunnel->output_handle, alloc_buffer_cb, on_outbround_udp_recv);
		static char comfirm[] = "connect target is ok.";
		size_t rsp_len = sizeof(comfirm) + (rand() % 0x80);
		char * rsp_data = (char*)malloc(rsp_len);
		if (rsp_data) {
			memcpy(rsp_data, comfirm, sizeof(comfirm));
			// 优化: 只清零填充部分
			if (rsp_len > sizeof(comfirm)) {
				memset(rsp_data + sizeof(comfirm), 0x00, rsp_len - sizeof(comfirm));
			}
			application_data_forword(tunnel, (const unsigned char *)rsp_data, rsp_len);
			xtrace(text_color_white, "on_outbround_listen_cb connect target success!");
			tunnel->stage = tunnel_stage_tls_streaming;
			free(rsp_data);
		}
		return;
	}

	//目标服务器解析或连接
	size_t offset = 0;
	struct socks5_address s5addr;
	if (!socks5_address_parse((const uint8_t*)socket->buf.base, socket->buf_len, &s5addr, &offset)) {
		tunnel->stage = tunnel_stage_shutdown;
		tunnel_dispatcher(tunnel, socket);
		return;
	}
	tunnel->target_addr.addr4.sin_port = s5addr.port;
	//带有认证信息的target request
	if (!tunnel->is_verified && socket->buf_len >= offset + sizeof(auth_info_t)) {
		struct auth_info authinfo;
		memcpy(&authinfo, socket->buf.base + offset, sizeof(auth_info_t));
		//打印认证信息
		char str_user_name[40] = { 0 };
		char str_user_cipher[40] = { 0 };
		uuid_to_string(authinfo.user_name, str_user_name);
		uuid_to_string(authinfo.user_cipher, str_user_cipher);
		xtrace(text_color_white,"do_inbround_target_request name:%s  cipher:%s", str_user_name, str_user_cipher);
		//认证逻辑处理,成功加入用户连接缓存列表
		char acc_key[256] = { 0 };
		sprintf(acc_key, "%d_%"PRIu64":%s@%s", authinfo.app_type, authinfo.user_id, str_user_name, str_user_cipher);
		if (usermgr_local_auth(my_usermgr, acc_key)) {
			uint8_t authinfo_md5[16] = {0};
			mbedtls_md5((uint8_t *)&authinfo, sizeof(struct auth_info), (uint8_t *)authinfo_md5);
			char key[40] = { 0 };
			uuid_to_string(authinfo_md5, (char*)key);
			if( usermgr_add_user(my_usermgr, key, &authinfo)){
				usermgr_online_save(my_usermgr);
			}
			xtrace(text_color_white, "do_inbround_target_request add new clinet key:%s", acc_key);
		}else {
			tunnel->stage = tunnel_stage_shutdown;
			tunnel_dispatcher(tunnel, socket);
			return;
		}
	}

	//S5提交的的域名处理
	if (s5addr.addr_type == SOCKS5_ADDRTYPE_DOMAINNAME) {
		//如果域名在已在缓存中存在
		union sockaddr_universal * query_addr = ip_addr_cache_retrieve_address(resolved_ip_cache, s5addr.addr.domainname, &malloc);
		if ( query_addr ) {
			struct sockaddr_in dest;
			dest.sin_family = AF_INET;
			dest.sin_port = htons(s5addr.port);
			dest.sin_addr = query_addr->addr4.sin_addr;
			tunnel->output_handle = (uv_handle_t*)malloc(sizeof(uv_tcp_t));
			uv_tcp_init(uv_default_loop(), (uv_tcp_t*)tunnel->output_handle);
			tunnel->output_handle->data = (void*)tunnel;
			uv_connect_t *conn_req = (uv_connect_t *)malloc(sizeof(uv_connect_t));
			memset(conn_req, 0x00, sizeof(uv_connect_t));
			conn_req->data = (void*)tunnel;
			int ret = uv_tcp_connect(conn_req, (uv_tcp_t*)tunnel->output_handle, (const struct sockaddr *)&dest, on_outbround_tcp_listen_cb);
			if( ret != 0 ) {
				xtrace(text_color_white, "do_inbround_target_request uv_tcp_connect ret:%d", ret);
				uv_close((uv_handle_t*)tunnel->output_handle, on_outbround_close_cb);
				free(conn_req);
			}
			xtrace(text_color_white, "do_inbround_target_request pull cache domain:%s ip:%s:%d", s5addr.addr.domainname, inet_ntoa(dest.sin_addr), s5addr.port);
			free(query_addr);
			return;
		}
		//域名不在缓存列表中，进行dns域名请求
		struct addrinfo hints;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		size_t domain_length = strlen(s5addr.addr.domainname) + 1;
		uv_getaddrinfo_t *query_req = (uv_getaddrinfo_t *)calloc(1, sizeof(*query_req));
		query_req->reserved[0] = (void*)malloc(domain_length);
		memset(query_req->reserved[0], 0x00, domain_length);
		strcpy(query_req->reserved[0], s5addr.addr.domainname);
		query_req->data = tunnel;
		xtrace(text_color_white,"uv_getaddrinfo_t domain:%s", query_req->reserved[0]);
		int ret = uv_getaddrinfo(uv_default_loop(), query_req, getaddrinfo_done_cb, s5addr.addr.domainname, NULL, &hints);
		if (ret != 0) {
			xtrace(text_color_white, "do_inbround_target_request uv_getaddrinfo ret:%d", ret);
			free(query_req->reserved[0]);
			free(query_req);
			query_req = NULL;
		}
		return;
	}

	//S5提交的是IP的处理
	else if (s5addr.addr_type == SOCKS5_ADDRTYPE_IPV4) {
		struct sockaddr_in dest;
		dest.sin_family = AF_INET;
		dest.sin_port = htons(s5addr.port);
		dest.sin_addr = s5addr.addr.ipv4;
		tunnel->output_handle = (uv_handle_t*)malloc(sizeof(uv_tcp_t));
		if (!tunnel->output_handle) {
			return;
		}
		uv_tcp_init(uv_default_loop(), (uv_tcp_t*)tunnel->output_handle);
		tunnel->output_handle->data = (void*)tunnel;
		uv_connect_t *conn_req = (uv_connect_t *)malloc(sizeof(uv_connect_t));
		if (!conn_req) {
			uv_close((uv_handle_t*)tunnel->output_handle, on_outbround_close_cb);
			return;
		}
		conn_req->data = (void*)tunnel;
		int ret = uv_tcp_connect(conn_req, (uv_tcp_t*)tunnel->output_handle, (const struct sockaddr *)&dest, on_outbround_tcp_listen_cb);
		if( ret != 0 ) {
			xtrace(text_color_white, "do_inbround_target_request uv_tcp_connect ret:%d", ret);
			uv_close((uv_handle_t*)tunnel->output_handle, on_outbround_close_cb);
			free(conn_req);
		}
		xtrace(text_color_white, "do_inbround_target_request connect target ip:%s port:%d", inet_ntoa(dest.sin_addr), s5addr.port);
	}
	return;
}

/**
* 关闭通道
* 只有 input 和 output 都断开后才释放通道
*/
void do_stage_shutdown(conn_context_t* tunnel) {
	if (tunnel->input_handle) {
		xtrace(text_color_white,"do_stage_shutdown to close input:%p", tunnel->input_handle);
		if (!uv_is_closing((uv_handle_t*)tunnel->input_handle)) {
			uv_close((uv_handle_t*)tunnel->input_handle, on_inbround_close_cb);
		}
	}
	else if (tunnel->output_handle) {
		xtrace(text_color_white, "do_stage_shutdown to close output:%p", tunnel->output_handle);
		if (!uv_is_closing((uv_handle_t*)tunnel->output_handle)) {
			uv_close((uv_handle_t*)tunnel->output_handle, on_outbround_close_cb);
		}
	}
	else if (tunnel->steal_handle) {
		xtrace(text_color_magenta, "do_stage_shutdown to close steal:%p", tunnel->steal_handle);
		if (!uv_is_closing((uv_handle_t*)tunnel->steal_handle)) {
			uv_close((uv_handle_t*)tunnel->steal_handle, on_steal_close_cb);
		}
	}
	if (tunnel->input_handle ==NULL &&  tunnel->output_handle == NULL &&  tunnel->steal_handle == NULL) {
		conn_channel_count--;
		xtrace(text_color_white, "do_stage_shutdown tunnel:%p flow:%d count:%d", tunnel, tunnel->flow_read_len,  conn_channel_count);
		if (check_tunnel_exists(tunnel)) {cstl_map_remove(my_tunnels, &tunnel);}
		mbedtls_ctr_drbg_free(&tunnel->ctr_drbg);
		mbedtls_entropy_free(&tunnel->entropy);
		mbedtls_ssl_config_free(&tunnel->conf);
		mbedtls_ssl_free(&tunnel->ssl_ctx);
		// 优化: 释放复用的缓冲区
		if (tunnel->input_read_buffer) {
			free(tunnel->input_read_buffer);
			tunnel->input_read_buffer = NULL;
			tunnel->input_read_buffer_capacity = 0;
		}
		if (tunnel->output_read_buffer) {
			free(tunnel->output_read_buffer);
			tunnel->output_read_buffer = NULL;
			tunnel->output_read_buffer_capacity = 0;
		}
		if (tunnel->ssl_read_buffer) {
			free(tunnel->ssl_read_buffer);
			tunnel->ssl_read_buffer = NULL;
			tunnel->ssl_read_buffer_capacity = 0;
		}
		free(tunnel);
	}
}

/**
 * steal handle 关闭回调
 */
void on_steal_close_cb(uv_handle_t *handle) {
	xtrace(text_color_magenta, "on_steal_close_cb handle");
	conn_context_t *conn_ctx = (conn_context_t *)handle->data;
	if (conn_ctx &&  conn_ctx->steal_handle ) {
		free(conn_ctx->steal_handle);
		conn_ctx->steal_handle = NULL;
	}
}

/**
 * 伪造样本获取流程
 */
static void on_steal_addrinfo_done_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs) {
	conn_context_t *tunnel = (conn_context_t *)req->data;
	if ( status==0 &&  addrs && check_tunnel_exists( tunnel ) ) {
		struct sockaddr_in dest = *(const struct sockaddr_in*)addrs->ai_addr;
		dest.sin_port = htons(/*tunnel->target_addr.addr4.sin_port*/ 443);
		tunnel->steal_handle = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
		if (!tunnel->steal_handle) {
			if(addrs)uv_freeaddrinfo(addrs);
			free(req->reserved[0]);
			free(req);
			return;
		}
		uv_tcp_init(uv_default_loop(), tunnel->steal_handle);
		tunnel->steal_handle->data = req->data;
		uv_connect_t *conn_req = (uv_connect_t *)malloc(sizeof(uv_connect_t));
		if (!conn_req) {
			uv_close((uv_handle_t*)tunnel->steal_handle, on_steal_close_cb);
			if(addrs)uv_freeaddrinfo(addrs);
			free(req->reserved[0]);
			free(req);
			return;
		}
		conn_req->data = req->data;
		int ret = uv_tcp_connect(conn_req, tunnel->steal_handle, (const struct sockaddr *)&dest, on_steal_listen_cb);
		if( ret != 0 ) {
			xtrace(text_color_white, "on_steal_addrinfo_done_cb uv_tcp_connect ret:%d", ret);
			uv_close((uv_handle_t*)tunnel->steal_handle, on_steal_close_cb);
			free(conn_req);
		}
	}
	if(addrs)uv_freeaddrinfo(addrs);	
	free(req->reserved[0]);
	free(req);
}

/**
 * 设置TLS版本支持
 */
int  update_tunnel_tls_configure(conn_context_t* tunnel) {
	xtrace(text_color_white, "update_tunnel_tls_configure ver:%04x", tunnel->tls_version);
	mbedtls_entropy_init(&tunnel->entropy);
	mbedtls_ctr_drbg_init(&tunnel->ctr_drbg);
	mbedtls_ssl_config_init(&tunnel->conf);
	mbedtls_ctr_drbg_seed(&tunnel->ctr_drbg, mbedtls_entropy_func, &tunnel->entropy, NULL, 0);  //播种随机数发生器 
	mbedtls_ssl_config_defaults(&tunnel->conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	mbedtls_ssl_conf_rng(&tunnel->conf, mbedtls_ctr_drbg_random, &tunnel->ctr_drbg);         // 设置随机数生成器
	mbedtls_ssl_conf_sni(&tunnel->conf, on_inbround_sni_callback, NULL);                                 // 设置 SNI 回调
	mbedtls_ssl_conf_authmode(&tunnel->conf, MBEDTLS_SSL_VERIFY_NONE);                         // 设置认证模式：不要求客户端证书
	mbedtls_ssl_conf_min_version(&tunnel->conf, MBEDTLS_SSL_MAJOR_VERSION_3, (tunnel->tls_version == 0x0304) ? MBEDTLS_SSL_MINOR_VERSION_4 : MBEDTLS_SSL_MINOR_VERSION_3);
	mbedtls_ssl_conf_max_version(&tunnel->conf, MBEDTLS_SSL_MAJOR_VERSION_3, (tunnel->tls_version == 0x0304) ? MBEDTLS_SSL_MINOR_VERSION_4 : MBEDTLS_SSL_MINOR_VERSION_3);
	if ( mbedtls_ssl_setup( &tunnel->ssl_ctx, &tunnel->conf) != 0 ) {
		xtrace(text_color_white, "update_tunnel_tls_configure mbedtls_ssl_setup failed");
		uv_close((uv_handle_t*)tunnel->input_handle, on_inbround_close_cb);
		return -1;
	}
	return 0;
}

/**
 * 收到客户端CH获取SNI后，缓存获取或偷取SH
 */
int on_inbround_sni_callback(void *p_info, mbedtls_ssl_context *ssl, const unsigned char *name, size_t name_len) {
	xtrace(text_color_white, "on_inbround_sni_callback sni:%s", name);
	conn_context_t *conn_ctx = (conn_context_t *)ssl->private_user_data.p;
	strncpy(conn_ctx->probe_sni, (const char*)name, min(name_len, sizeof(conn_ctx->probe_sni) - 1));

	//check sessionID is inno-reality protocol
	unsigned char session_buf[32] = { 0 };
	mbedtls_ssl_get_client_sessionid(&conn_ctx->ssl_ctx, session_buf);
	if (!check_session_id(session_buf)) {
		xtrace(text_color_white, "on_inbround_sni_callback  probe handle");
		conn_ctx->is_probe = true;
		do_probe_connect(conn_ctx, NULL);
		return 0;
	}

	//verity user token
	struct session_id session_id = { 0 };
	char token_for_key[40] = { 0 };
	memcpy(&session_id, session_buf, 32);
	uuid_to_string(session_id.token, token_for_key);
	htrace(text_color_white, "on_inbround_sni_callback session id", session_buf, 32);
	if (session_id.pkg_type == 0x01 ) { 			                                                        //只有当pkg_type==1时，才需要进行验证。
		xtrace(text_color_white, "on_inbround_sni_callback usermgr_is_online ");
		if (usermgr_is_online(my_usermgr, token_for_key)) {
			conn_ctx->is_verified = true;
		}else {
			xtrace(text_color_white, "on_inbround_sni_callback shutdown");
			conn_ctx->stage = tunnel_stage_shutdown;
			tunnel_dispatcher(conn_ctx, NULL);
			return 0;
		}
	}

	//私钥
	static mbedtls_pk_context spk;
	static bool pk_exist = false;
	if ( !pk_exist ) {
		pk_exist = true;
		mbedtls_pk_init(&spk);
		mbedtls_pk_parse_key(&spk, (const unsigned char *)s_mbedtls_test_srv_key_rsa, strlen(s_mbedtls_test_srv_key_rsa) + 1,
														(const unsigned char *)s_mbedtls_test_srv_pwd_rsa, strlen(s_mbedtls_test_srv_pwd_rsa), NULL, 0);
	}

	//从证书书列表中获取添加证书
	struct cert_data * crtinfo = get_cert_info(my_certmgr, name);
	if ( crtinfo ) {
		int ret = mbedtls_ssl_set_hs_own_cert(ssl, crtinfo->cert, &spk);
		if (ret != 0) { xtrace(text_color_red, "mbedtls_ssl_set_hs_own_cert failed: %d\n", ret); }
		conn_ctx->stage = tunnel_stage_tls_handshake;
		tunnel_dispatcher(conn_ctx, NULL);
		return 0;
	}

	//没有证书，最后兜底直接采用内置证书
	static mbedtls_x509_crt scrt;
	static bool cert_exist = false;
	if (!cert_exist) {
		cert_exist = true;
		mbedtls_x509_crt_init(&scrt);
		int ret = mbedtls_x509_crt_parse(&scrt, (const unsigned char *)s_mbedtls_test_srv_crt_rsa, strlen(s_mbedtls_test_srv_crt_rsa) + 1);
		if (ret != 0) { xtrace(text_color_red, "crt_parse failed: %d\n", ret);}
	}
	int ret = mbedtls_ssl_set_hs_own_cert(ssl, &scrt, &spk);
	if (ret != 0) { xtrace(text_color_red, "mbedtls_ssl_set_hs_own_cert failed: %d\n", ret); }
	conn_ctx->stage = tunnel_stage_tls_handshake;
	tunnel_dispatcher(conn_ctx, NULL);
	return 0;
}

/**
 * 窃取监听回调
 */
void on_steal_listen_cb(uv_connect_t *req, int status) {
	conn_context_t * tunnel = (conn_context_t *)req->data;
	if (check_tunnel_exists(tunnel) ) {
		if (status < 0) {
			xtrace(text_color_magenta, "on_steal_listen_cb  conn fail: %s", uv_strerror(status));
			tunnel->stage = tunnel_stage_shutdown;
			tunnel_dispatcher(tunnel, NULL);
			free(req);
			return;
		}
		if (tunnel->steal_handle) {
			uv_read_start((uv_stream_t *)tunnel->steal_handle, alloc_buffer_cb, on_steal_read_cb);
			socket_tcp_write((uv_stream_t*)tunnel->steal_handle, tunnel->input_read_buffer, tunnel->input_read_buffer_len);
		}
	}
	free(req);
}

/**
 * 收到偷取的ClientHello&Cert, 发送给客户端
 */
void on_steal_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
	conn_context_t *conn_ctx = (conn_context_t *)stream->data;
	if ( conn_ctx && stream && nread <= 0 ) {
		xtrace(text_color_magenta, "on_steal_read_cb [%d] to close", nread);
		uv_close((uv_handle_t*)stream, on_steal_close_cb);
		if (buf && buf->base) {buffer_pool_release(buf->base);}
		return;
	}
	if (!conn_ctx || !stream) {
		if (buf && buf->base) buffer_pool_release(buf->base);
		return;
	}
	htrace(text_color_magenta, "on_steal_read_cb read server_hello from server", buf->base, nread);
	uint8_t * ibuf = buf->base;
	for (size_t pos = 0; pos + 12 <= (size_t)nread; pos++) {
		//从server_hello 获取TLS版本号
		if (ibuf[pos] == 0x16 && ibuf[pos + 1] == 0x03 && ibuf[pos + 2] == 0x03 && ibuf[pos + 5] == 0x02) {
			unsigned int sh_len = ibuf[pos + 3];
			sh_len = (sh_len << 8) + ibuf[pos + 4] + 5 ;
			if (pos + sh_len > (size_t)nread) break;
			if ( parse_server_hello_tlsversion(&ibuf[pos], sh_len, &conn_ctx->tls_version) == 0) {
				certmgr_add_pem(my_certmgr, conn_ctx->probe_sni, conn_ctx->tls_version, NULL, 0 );
				xtrace(text_color_magenta, "on_steal_read_cb server tls1.3 information domain:%s version:%04X", conn_ctx->probe_sni, conn_ctx->tls_version);
			}
			update_tunnel_tls_configure(conn_ctx);
			if (conn_ctx->tls_version == 0x0304){  //只有TLS1.3在此退出，因为取不到证书长度了
				conn_ctx->stage = tunnel_stage_tls_clientHello;
				tunnel_dispatcher(conn_ctx, NULL);
				break;
			}
			if( pos + sh_len > (size_t)nread) break;
			pos += sh_len - 1;
		}
		//从ceritificate 获取证书长度
		if (pos + 12 <= (size_t)nread && ibuf[pos] == 0x16 && ibuf[pos + 1] == 0x03 && ibuf[pos + 2] == 0x03 && ibuf[pos + 5] == 0x0B) {
			unsigned int cert_len = ibuf[pos + 9];
			cert_len = (cert_len << 16) + (ibuf[pos + 10] << 8) + ibuf[pos + 11];
			xtrace(text_color_magenta, "on_steal_read_cb server tls1.2 ceritificate domain:%s certlen:%d", conn_ctx->probe_sni, cert_len);
			uv_close((uv_handle_t*)stream, on_steal_close_cb);
			certmgr_add_pem(my_certmgr, conn_ctx->probe_sni, conn_ctx->tls_version, &ibuf[pos], cert_len);
			conn_ctx->stage = tunnel_stage_tls_clientHello;
			tunnel_dispatcher(conn_ctx, NULL);
			break;
		}
	}
	if (buf && buf->base) buffer_pool_release(buf->base);
	return;
}

/**
 * 偷证书处理流程开始
 */
void do_steal_handle( conn_context_t* tunnel) {
#ifdef ASYNC_LIBUV_PROC
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	size_t domain_length = strlen(tunnel->probe_sni) + 1;
	uv_getaddrinfo_t *query_req = (uv_getaddrinfo_t *)calloc(1, sizeof(*query_req));
	query_req->reserved[0] = (void*)malloc(domain_length);
	memset(query_req->reserved[0], 0x00, domain_length);
	strcpy(query_req->reserved[0], tunnel->probe_sni);
	query_req->data = tunnel;
	int ret = uv_getaddrinfo(uv_default_loop(), query_req, on_steal_addrinfo_done_cb, tunnel->probe_sni, NULL, &hints);
	if (ret != 0) {
		xtrace(text_color_white, "on_steal_read_cb uv_getaddrinfo ret:%d", ret);
		free(query_req->reserved[0]); 
		free(query_req);
		query_req = NULL;
	}
	return;
#endif
	//采用同步mbedtls方式获取证书信息
	certmgr_steal_cert(my_certmgr, tunnel->probe_sni, &tunnel->tls_version);
	xtrace(text_color_magenta, "do_steal_handle certmgr_steal_cert domain:%s ver:%04X", tunnel->probe_sni, tunnel->tls_version);
	update_tunnel_tls_configure(tunnel);
	tunnel->stage = tunnel_stage_tls_clientHello;
	tunnel_dispatcher(tunnel, NULL);
	return;
}

/**
 * udp 发送回调
 */
void on_outbround_udp_send_cb(uv_udp_send_t* req, int status) {
	if (req->data) {
		free(req->data);
	}
	free(req);
}

/**
 * S5 UDP接收数据
 */
void on_outbround_udp_recv(uv_udp_t* handle, ssize_t nread, const uv_buf_t* rcvbuf, const struct sockaddr* addr, unsigned flags) {
	if (nread <= 0) {
        if (rcvbuf && rcvbuf->base) buffer_pool_release(rcvbuf->base);
        return;
    }
	//这里将通过 tcp 转发回给客户端
	if( handle && rcvbuf && rcvbuf->base ) {
		htrace(text_color_white, "on_udp_recv", rcvbuf->base, nread);
		conn_context_t *conn_ctx = (conn_context_t *)handle->data;
		socket_ctx_t  ctx;
		ctx.buf = uv_buf_init(rcvbuf->base, nread);
		ctx.buf_len = nread;
		ctx.handle = conn_ctx->output_handle;
		tunnel_dispatcher(conn_ctx, &ctx);
		buffer_pool_release(rcvbuf->base);
	}
}

/**
 * tls 数据传输
 */
void do_stage_forword(conn_context_t* tunnel, socket_ctx_t* socket) {
	if (!tunnel || !socket) {
        xtrace(text_color_red, "do_stage_forword: invalid parameters");
        return;
    }
	char * data = socket->buf.base;
	size_t  size = (size_t)socket->buf_len;
#ifdef WIN32                                                                                                                          
	if (tunnel->input_handle && tunnel->output_handle && ((uv_tcp_t*)socket->handle)->socket == tunnel->input_handle->socket) {
#else
	if (tunnel->input_handle && tunnel->output_handle &&  socket->handle == (uv_handle_t*)tunnel->input_handle) {
#endif
		if (tunnel->is_uot) {
			socket_udp_write((uv_udp_t*)tunnel->output_handle, (const struct sockaddr*)&tunnel->udp_dest, data, size);
		}else {
			socket_tcp_write((uv_stream_t*)tunnel->output_handle, data, size);
		}
		return;
	}
#ifdef WIN32
	if (tunnel->output_handle && ((uv_tcp_t*)socket->handle)->socket == ((uv_tcp_t*)tunnel->output_handle)->socket) {
#else
	if (tunnel->output_handle && socket->handle == tunnel->output_handle) {
#endif 
		if (tunnel->is_handle_tlsintls) {
			socket_tcp_write((uv_stream_t*)tunnel->output_handle, data, size);
		}else {
			application_data_forword(tunnel, (const unsigned char*)data, size);
		}
		return;
	}
	xtrace(text_color_white, "do_stage_forword handless size:%d", size);
}

/**
 * dispath (隧道状态机调度函数)
 */
static void tunnel_dispatcher(conn_context_t* tunnel, socket_ctx_t* socket) {
	//xtrace(text_color_yellow, "tunnel_dispatcher enter case:%s", tunnel_stage_string(tunnel->stage));
	switch (tunnel->stage) {
	case tunnel_stage_tls_clientHello:
		do_inbround_handshake(tunnel);
		break;

	case tunnel_stage_tls_stealhandle: 
		do_steal_handle(tunnel);
		break;

	case tunnel_stage_tls_handshake:
		do_inbround_handshake(tunnel);
		break;

	case tunnel_stage_tls_handshaked:
		do_inbround_target_request(tunnel, socket);
		break;

	case tunnel_stage_tls_streaming:
		do_stage_forword(tunnel, socket);
		break;

	case tunnel_stage_probe_streaming:
		do_probe_forword(tunnel, socket);
		break;

	case tunnel_stage_shutdown:
		do_stage_shutdown(tunnel);
		break;
	}
}

/**
 * Walk callback for closing all handles
 */
static void close_walk_cb(uv_handle_t *handle, void *arg) {
	(void)arg;
	if (!uv_is_closing(handle)) {
		uv_close(handle, NULL);
	}
}

/**
 * Signal handler (Ctrl+C)
 */
static void on_signal(uv_signal_t *handle, int signum) {
	(void)handle;
	(void)signum;
	printf("Ctrl+c to Exit.\n");
	uv_walk(uv_default_loop(), close_walk_cb, NULL);
}

/**
 * TTY read callback for stdin
 */
static void on_stdin_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
	(void)stream;
	if (nread < 0) {
		if (nread == UV_EOF) {
			printf("\nEOF received, shutting down...\n");
			uv_walk(uv_default_loop(), close_walk_cb, NULL);
		}else {
			fprintf(stderr, "[ERROR] stdin read error: %s\n", uv_strerror((int)nread));
		}
		goto cleanup;
	}
	if (nread > 0) {
		char *input = (char*)malloc(nread + 1);
		memcpy(input, buf->base, nread);
		input[nread] = '\0';
		/* Remove newlines */
		char *p = input;
		while (*p) {
			if (*p == '\n' || *p == '\r') { *p = '\0'; break; }
			p++;
		}
		if (strcmp(input, "quit") == 0 || strcmp(input, "exit") == 0) {
			uv_walk(uv_default_loop(), close_walk_cb, NULL);
		}
		else if (strcmp(input, "print online") == 0) {
			print_online_user(my_usermgr);
		}
		else if (strcmp(input, "print local") == 0) {
			print_local_user(my_usermgr);
		}
		else if (strcmp(input, "print fake") == 0) {
			print_probe_domain(my_certmgr);
		}
		else if (strcmp(input, "print dns") == 0) {
			print_domain_address(resolved_ip_cache);
		}
		else {
			printf("Unknown command: '%s'. Type 'help' for available commands.\n", input);
			printf("> ");
			fflush(stdout);
		}
		free(input);
	}
cleanup:
	if (buf->base) {
		buffer_pool_release(buf->base);
	}
}

/**
 * main 主函数
 */
int main(int argc, char * argv[]) {
	xtrace(text_color_white, "inno reality - server (optimized)");
	uv_loop_t *loop = uv_default_loop();
	srand((unsigned int)time(NULL));
	buffer_pool_init(); 	// 优化: 初始化内存池
	my_config = configure_create(argc, argv);
	resolved_ip_cache = ip_addr_cache_create(IP_CACHE_EXPIRE_INTERVAL_MIN);
	my_usermgr = usermgr_create();
	my_certmgr = certmgr_create();
	my_tunnels = cstl_map_new(compare_tunnel, NULL, NULL);
	certmgr_add_cert(my_certmgr, "test.com", 0x0303, s_mbedtls_test_srv_crt_rsa); 	//添加默认域名证书
	//启动inbround tcp服务
	uv_tcp_t server_socket;
	struct sockaddr_in addr;
	uv_tcp_init(loop, &server_socket);
	uv_ip4_addr("0.0.0.0", my_config->port, &addr);
	int ret = uv_tcp_bind(&server_socket, (const struct sockaddr*)&addr, 0);
	if( ret != 0 ) {
		xtrace(text_color_white, "main uv_tcp_bind ret:%d", ret);
		uv_close((uv_handle_t*)&server_socket, NULL);
		goto cleanup;
	}
	int lsn = uv_listen((uv_stream_t*)&server_socket, 1024, on_inbround_listen_cb);
	if( lsn != 0 ) {
		xtrace(text_color_white, "main uv_listen ret:%d", lsn);
		uv_close((uv_handle_t*)&server_socket, NULL);
		goto cleanup;
	}
	xtrace(text_color_white, "start server listening on:%d error:%s", my_config->port, uv_strerror(lsn));
	//启动 stdin reading(TTY)
	int r = uv_tty_init(loop, &tty_stdin, 0, 1);  /* 0 = stdin, 1 = readable */
	if (r >= 0) {
		r = uv_read_start((uv_stream_t*)&tty_stdin, alloc_buffer_cb, on_stdin_read_cb);
		if (r < 0) {
			fprintf(stderr, "Warning: stdin read start failed: %s\n", uv_strerror(r));
		}
	}
	//安装 signal handler for Ctrl+C信号
	uv_signal_init(loop, &signal_handle);
	uv_signal_start(&signal_handle, on_signal, SIGINT);
	xtrace(text_color_white, "Press Ctrl+C or type 'quit' to stop\n");
	printf("> ");
	fflush(stdout);
	uv_run(loop, UV_RUN_DEFAULT);
	uv_loop_close(loop);
cleanup:
	//释放配置、缓存和用户管理器资源
	buffer_pool_destroy();
	cstl_map_delete(my_tunnels);
	ip_addr_cache_destroy(resolved_ip_cache);
	configure_destroy(my_config);
	usermgr_destroy(my_usermgr);
	certmgr_destroy(my_certmgr);
	xtrace(text_color_white, "safe exit.\n");
	return 0;
}
