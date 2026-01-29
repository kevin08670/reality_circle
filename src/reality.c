// xClient.c : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <time.h>
#include <uv.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl_cache.h>
#include <mbedtls/md5.h>
#ifdef _WIN32
#include <windows.h>
#define ATOMIC_UINT volatile LONG
#define ATOMIC_BOOL volatile LONG
#define ATOMIC_INC(x) InterlockedIncrement(&(x))
#define ATOMIC_DEC(x) InterlockedDecrement(&(x))
#define ATOMIC_STORE_BOOL(x, v) InterlockedExchange(&(x), (v) ? 1 : 0)
#define ATOMIC_LOAD_BOOL(x) (InterlockedOr(&(x), 0) != 0)
#else
#include <stdatomic.h>
#define ATOMIC_UINT atomic_uint
#define ATOMIC_BOOL atomic_bool
#define ATOMIC_INC(x) atomic_fetch_add(&(x), 1)
#define ATOMIC_DEC(x) atomic_fetch_sub(&(x), 1)
#define ATOMIC_STORE_BOOL(x, v) atomic_store(&(x), v)
#define ATOMIC_LOAD_BOOL(x) atomic_load(&(x))
#endif
#include "s5.h"                            //SOCKS5 协议处理
#include "text_in_color.h"           //用于彩色输出的辅助文件
#include "sockaddr_universal.h" //通用地址结构体
#include "configure.h"                //配置信息
#include "mycert.h"                    //默认证书

// http://ipv4.download.thinkbroadband.com/20MB.zip  // 示例下载链接，可能是测试用
#define TLSINTLS_HANDLE     1 // 开启 TlsinTls 处理, 只有 TLS1.3 才能开启 (此处注释提及TLS1.3，但代码中强制限制为TLS1.2)

// ============ 性能优化配置 ============
#define FRAME_SIZE                          16384            // 优化: 从60000减少到16KB，更适合TLS记录大小(16KB限制)
#define BUFFER_POOL_SIZE              32                  // 缓冲池大小
#define INITIAL_BUFFER_CAPACITY  32768            // 初始缓冲区容量 32KB
#define MAX_BUFFER_CAPACITY     (1024*1024)   // 最大缓冲区容量 1MB

/* Session states. */
// 隧道连接的阶段映射宏
#define TUNNEL_STAGE_MAP(V)   \
    V( 0, tunnel_stage_s5_handshake, "tunnel_stage_s5_handshake")  \
    V( 1, tunnel_stage_s5_connrequest,  "tunnel_stage_s5_connrequest")  \
    V( 2, tunnel_stage_tls_handshak,  "tunnel_stage_tls_handshak")  \
	V( 3, tunnel_stage_tls_handshaked,  "tunnel_stage_tls_handshaked")  \
    V( 4, tunnel_stage_intent_target,  "tunnel_stage_intent_target")  \
    V( 5, tunnel_stage_streaming,  "tunnel_stage_streaming")  \
    V( 6, tunnel_stage_shutdown,  "tunnel_stage_shutdown")  \

// 隧道连接的阶段枚举
enum tunnel_stage {
#define TUNNEL_STAGE_GEN(code, name, _) name = code,
	TUNNEL_STAGE_MAP(TUNNEL_STAGE_GEN)
#undef TUNNEL_STAGE_GEN
	tunnel_stage_max,
};

// 阶段枚举转换为字符串
static const char* tunnel_stage_string(enum tunnel_stage stage) {
#define TUNNEL_STAGE_GEN(_, name, name_str) case name: return name_str;
	switch (stage) {
		TUNNEL_STAGE_MAP(TUNNEL_STAGE_GEN)
	default:
		return "Unknown stage.";
	}
#undef TUNNEL_STAGE_GEN
}

// TCP 连接上下文 (用于通用 socket 操作)
typedef struct socket_ctx {
	uv_handle_t * handle;
	struct uv_buf_t buf;
	size_t buf_len;
}socket_ctx_t;

// ============ 简单内存池实现 ============
typedef struct buffer_pool_item {
	char *buffer;
	size_t capacity;
	int in_use;
} buffer_pool_item_t;

static buffer_pool_item_t g_buffer_pool[BUFFER_POOL_SIZE];
static ATOMIC_UINT        g_conn_context_count;                        // 当前连接数
static ATOMIC_BOOL       g_had_verified; 			                         // 是否已完成身份验证 (用于会话ID或首次发送数据)

struct reality_client_state {
	struct server_env_t *env;
	void(*feedback_state)(void *p, struct reality_client_state *state, const char* info);
	void *ptr;
	// 成员定义 (全局变量)
	struct configure * my_config;              // 程序配置
	auth_info_t  my_authinfo;                    // 身份验证信息
	uint8_t  my_authinfo_md5[16];            // 身份验证信息的 MD5
	uv_signal_t signal_handle;
};

// VPN 连接上下文 (核心结构体，保存隧道状态)
typedef struct conn_context {
	struct reality_client_state * state;
	enum tunnel_stage stage;                   //当前隧道阶段
	uv_tcp_t * input_tcp_handle;               //客户端连接 (SOCKS5 TCP)
	uv_udp_t * input_udp_handle;            //客户端连接 (SOCKS5 UDP)
	char *input_read_buffer;
	size_t input_read_buffer_len;
	size_t input_read_buffer_offset;
	uv_tcp_t * output_handle;                   //远程服务器连接 (VPS/TLS)
	char *output_read_buffer;                   //远程服务器接收数据的缓存 (用于 mbedTLS 接收回调)
	size_t output_read_buffer_len;
	size_t output_read_buffer_offset;
	size_t output_read_buffer_capacity;     //优化: 预分配容量，减少 realloc 次数
	mbedtls_ssl_context ssl_ctx;                //mbedTLS SSL/TLS 上下文
	mbedtls_ssl_config conf;                     //Mbedtls 相关配置
	mbedtls_x509_crt cacert;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_cache_context cache;
	size_t inbround_read_len;                   //发送的总数
	size_t outbround_read_len;                 //接收的总数
	struct uv_buf_t target_address_pkg;   //SOCKS5 目标地址请求包
	bool is_handle_tlsintls;                        //是否启用 TLS-in-TLS 转发 (直接转发 TLS 记录)
	bool is_had_intent_target;                  //是否发送目标声明
	bool is_mbedtls_initialized;                 //mbedTLS 资源是否已初始化 (用于安全释放)
	struct sockaddr s5_src_addr;              //S5 udp 源地址
	struct sockaddr s5_dst_addr;              //S5 udp 目标地址
	unsigned char *ssl_read_buffer;          //优化: TLS解密数据复用缓冲区
	size_t ssl_read_buffer_capacity;          //优化: TLS解密缓冲区容量
} conn_context_t;

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
static void buffer_pool_destroy(void) {
	for (int i = 0; i < BUFFER_POOL_SIZE; i++) {
		if (g_buffer_pool[i].buffer) {
			free(g_buffer_pool[i].buffer);
			g_buffer_pool[i].buffer = NULL;
		}
		g_buffer_pool[i].in_use = 0;
	}
}

//需要声明的函数
static void tunnel_dispatcher(conn_context_t* tunnel, socket_ctx_t* socket);
int my_mbedtls_send(void *ctx, const unsigned char *buf, size_t len);
int my_mbedtls_recv(void *ctx, unsigned char *buf, size_t len);
void on_outbound_connect_cb(uv_connect_t *req, int status);
void on_inbround_udp_recv(uv_udp_t* handle, ssize_t nread, const uv_buf_t* rcvbuf, const struct sockaddr* addr, unsigned flags);
void uv_inbround_udp_send_cb(uv_udp_send_t* req, int status);

/**
 * socket 写入完成回调
 */
static void socket_write_done_cb(uv_write_t* req, int status) {
	if (status != 0) { xtrace(text_color_red, "socket_write_done_cb %s ret:%d", uv_err_name(status), status); }
	char *write_buf = (char *)req->data;
	if (write_buf) buffer_pool_release(write_buf);
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
		// P0: 部分写入时只对剩余部分做异步发送，避免重复发已写字节并丢尾段
		if (written > 0 && written < (ssize_t)len) {
			data = (const char *)data + written;
			len -= (size_t)written;
		}
	}
	// 异步写入路径：len<=FRAME_SIZE 优先从缓冲池获取，减少 malloc
	uv_write_t *req = (uv_write_t *)malloc(sizeof(uv_write_t));
	if (!req) return -1;
	size_t cap = 0;
	char *write_buf = (len <= (size_t)FRAME_SIZE)? buffer_pool_get(&cap): (char *)malloc(len);
	if (!write_buf) {
		free(req);
		return -1;
	}
	memcpy(write_buf, data, len);
	req->data = write_buf;
	uv_buf_t buf = uv_buf_init(write_buf, (unsigned int)len);
	int ret = uv_write(req, stream, &buf, 1, socket_write_done_cb);
	if (ret != 0) {
		xtrace(text_color_white, "socket_tcp_write ret:%d", ret);
		buffer_pool_release(write_buf); /* 非池则 free */
		free(req);
		return ret;
	}
	return (int)len;
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
	int ret = uv_udp_send(send_req, handle, &send_buf, 1, addr, uv_inbround_udp_send_cb);
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
 */
void alloc_buffer_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
	size_t capacity = 0;
	buf->base = buffer_pool_get(&capacity);
	buf->len = (buf->base) ? (unsigned int)capacity : 0;
}

/**
 *  释放 SOCKS5 (客户端) 连接资源回调
 */
void on_inbound_close_cb(uv_handle_t *handle) {
	//xtrace(text_color_white, "on_inbound_close_cb handle");
	conn_context_t *conn_ctx = (conn_context_t *)handle->data;
	// 只释放当前关闭的 handle
	if ((uv_handle_t*)conn_ctx->input_tcp_handle == handle) {
		free(conn_ctx->input_tcp_handle);
		conn_ctx->input_tcp_handle = NULL;
		if (conn_ctx->input_read_buffer) {
			free(conn_ctx->input_read_buffer);
			conn_ctx->input_read_buffer = NULL;
		}
	}
	else if ((uv_handle_t*)conn_ctx->input_udp_handle == handle) {
		free(conn_ctx->input_udp_handle);
		conn_ctx->input_udp_handle = NULL;
	}
	conn_ctx->stage = tunnel_stage_shutdown;
	tunnel_dispatcher(conn_ctx, NULL);
}

/**
 * 读数据回调函数 (SOCKS5 客户端数据到达)
 * 优化: 使用内存池归还缓冲区
 */
void on_inbound_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
	conn_context_t *conn_ctx = (conn_context_t *)stream->data;
	if (nread < 0) {
		uv_close((uv_handle_t*)stream, on_inbound_close_cb);
		if (buf->base) buffer_pool_release(buf->base);
		return;
	}
	htrace(text_color_green, "on_inbound_read_cb", buf->base, nread);
	socket_ctx_t  ctx;
	ctx.buf = uv_buf_init(buf->base, (unsigned int)nread);
	ctx.buf_len = nread;
	ctx.handle = (uv_handle_t*)conn_ctx->input_tcp_handle;
	tunnel_dispatcher(conn_ctx, &ctx);
	buffer_pool_release(buf->base);
}

/** P0: uv_accept 失败时仅在关闭回调中 free handle，避免 uv_close 异步导致的 use-after-free */
static void on_accept_failed_close_cb(uv_handle_t *handle) {
	free(handle);
}

/**
 * SOCKS5 监听回调 (新客户端连接到达)
 * 优化: 减少调试输出
 */
void on_inbound_listen_cb(uv_stream_t *server, int status) {
	if (status < 0) {
		xtrace(text_color_red, "on_inbound_listen_cb connection error: %s\n", uv_strerror(status));
		return;
	}
	uv_tcp_t * input_handle = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
	uv_tcp_init(server->loop, input_handle);
	// 2. 接受新连接
	if (uv_accept(server, (uv_stream_t *)input_handle) != 0) {
		xtrace(text_color_red, "uv_accept error.");
		uv_close((uv_handle_t*)input_handle, on_accept_failed_close_cb);
		return;
	}
	// 1. 创建并初始化连接上下文
	uv_tcp_nodelay(input_handle, 1);
	uv_tcp_keepalive(input_handle, 1, 60);
	conn_context_t *conn_ctx = (conn_context_t*)malloc(sizeof(conn_context_t));
	memset(conn_ctx, 0, sizeof(conn_context_t));
	conn_ctx->state = (struct reality_client_state *)server->data;
	conn_ctx->input_tcp_handle = input_handle;
	conn_ctx->input_tcp_handle->data = (void*)conn_ctx; // 将上下文绑定到 handle
	conn_ctx->stage = tunnel_stage_s5_handshake; // 初始阶段：SOCKS5 握手
	ATOMIC_INC(g_conn_context_count);
	// 3. 开始读取，等待 SOCKS5 Hello 数据
	uv_read_start((uv_stream_t *)conn_ctx->input_tcp_handle, alloc_buffer_cb, on_inbound_read_cb);
	xtrace(text_color_white, "on_inbound_listen_cb new connection, conn_context_count:%ld", g_conn_context_count);
}

/**
 * 接收 SOCKS5 Hello 包 (阶段 0)
 * 优化: 减少调试输出
 */
void do_inbound_handshake(conn_context_t* tunnel, socket_ctx_t* socket) {
	if( !tunnel || !socket ){
		return;
	}
	xtrace(text_color_white, "do_inbound_handshake.");
	struct s5_ctx* parser = s5_ctx_create();
	uint8_t* data = (uint8_t*)socket->buf.base;
	size_t size = (size_t)socket->buf_len;
	enum s5_result  result = s5_parse(parser, &data, &size);
	if (result == s5_result_need_more) {
		s5_ctx_release(parser); 
		return;
	}
	tunnel->stage = tunnel_stage_s5_connrequest;
	socket_tcp_write((uv_stream_t*)socket->handle, "\5\0", 2);
	s5_ctx_release(parser); 
}

/**
 * 接收 SOCKS5 请求地址包 (阶段 1)
 */
void do_inbound_handshake_connvps(conn_context_t* tunnel, socket_ctx_t* socket) {
	if(!tunnel || !socket){
		return;
	}
	struct s5_ctx* parser = s5_ctx_create();
	uint8_t* data = (uint8_t*)socket->buf.base;
	size_t size = (size_t)socket->buf_len;
	if (socket->buf_len < 2) {
		s5_ctx_release(parser);
		return;
	}
	uint8_t s5_cmd = data[1];
	enum s5_result  result = s5_parse(parser, &data, &size); // 解析 SOCKS5 连接请求包
	if (result == s5_result_need_more) {
		xtrace(text_color_red, "do_inbound_handshake_connvps  s5_result_need_more");
		s5_ctx_release(parser);
		return;
	}
	s5_ctx_release(parser);
	//UDP传透处理
	if ( s5_cmd == 0x03 ) {
		tunnel->input_udp_handle = (uv_udp_t*)malloc(sizeof(uv_udp_t));
		tunnel->input_udp_handle->data = tunnel;
		struct sockaddr_in addr_udp;
		uv_udp_init(uv_default_loop(), tunnel->input_udp_handle);
		uv_ip4_addr(tunnel->state->my_config->local_host, 0, &addr_udp);
		int nRet = uv_udp_bind(tunnel->input_udp_handle, (const struct sockaddr*)&addr_udp, UV_UDP_REUSEADDR);
		if (nRet != 0) {
			xtrace(text_color_red, "do_inbound_handshake_connvps uv_udp_bind failed: %s", uv_strerror(nRet));
			uv_close((uv_handle_t*)tunnel->input_udp_handle, on_inbound_close_cb);
			// 关闭 input_tcp_handle 触发完整清理流程
			uv_close((uv_handle_t*)tunnel->input_tcp_handle, on_inbound_close_cb);
			return;
		}
		uv_udp_recv_start(tunnel->input_udp_handle, alloc_buffer_cb, on_inbround_udp_recv);
		// 连接 VPS 服务器 (远程服务器)
		uv_loop_t *loop = uv_default_loop();
		tunnel->output_handle = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
		uv_tcp_init(loop, tunnel->output_handle);
		uv_tcp_nodelay(tunnel->output_handle, 1);
		tunnel->output_handle->data = (void*)tunnel; // 绑定上下文
		tunnel->ssl_ctx.private_state = 0; // mbedtls_ssl_init 会设置
		uv_connect_t *connect_req = (uv_connect_t *)malloc(sizeof(uv_connect_t));
		connect_req->data = tunnel;
		struct sockaddr_in dest;
		uv_ip4_addr(tunnel->state->my_config->remote_host, tunnel->state->my_config->remote_port, &dest);
		int ret = uv_tcp_connect(connect_req, tunnel->output_handle, (const struct sockaddr *)&dest, on_outbound_connect_cb);
		if (ret != 0) {
			xtrace(text_color_red, "do_inbound_handshake_connvps UDP uv_tcp_connect failed: %s", uv_strerror(ret));
			free(connect_req);
			free(tunnel->output_handle);
			tunnel->output_handle = NULL;
			// 关闭 UDP 和 TCP input 触发完整清理
			uv_close((uv_handle_t*)tunnel->input_udp_handle, on_inbound_close_cb);
			uv_close((uv_handle_t*)tunnel->input_tcp_handle, on_inbound_close_cb);
			return;
		}
		xtrace(text_color_white, "do_inbound_handshake_connvps output flag:%u.", tunnel->output_handle->flags);
		return;
	}
	// 保存目标地址包，后续通过 TLS 发送到 VPS
	tunnel->target_address_pkg = uv_buf_init((char*)malloc(size), size);
	memcpy(tunnel->target_address_pkg.base, data, size);
	// 连接 VPS 服务器 (远程服务器)
	uv_loop_t *loop = uv_default_loop();
	tunnel->output_handle = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
	uv_tcp_init(loop, tunnel->output_handle);
	uv_tcp_nodelay(tunnel->output_handle, 1);
	tunnel->output_handle->data = (void*)tunnel; // 绑定上下文
	tunnel->ssl_ctx.private_state = 0; // mbedtls_ssl_init 会设置
	uv_connect_t *connect_req = (uv_connect_t *)malloc(sizeof(uv_connect_t));
	connect_req->data = tunnel;
	struct sockaddr_in dest;
	uv_ip4_addr(tunnel->state->my_config->remote_host, tunnel->state->my_config->remote_port, &dest);
	int ret = uv_tcp_connect(connect_req, tunnel->output_handle, (const struct sockaddr *)&dest, on_outbound_connect_cb);
	if (ret != 0) {
		xtrace(text_color_red, "do_inbound_handshake_connvps uv_tcp_connect failed: %s", uv_strerror(ret));
		free(connect_req);
		free(tunnel->output_handle);
		tunnel->output_handle = NULL;
		if (tunnel->target_address_pkg.base) {
			free(tunnel->target_address_pkg.base);
			tunnel->target_address_pkg.base = NULL;
		}
		// 关闭 input 连接
		uv_close((uv_handle_t*)tunnel->input_tcp_handle, on_inbound_close_cb);
	}
}

/**
 * 连接远程服务器后才返回 SOCKS5 确认给发起端 (阶段 3)
 * 优化: 减少调试输出
 */
void do_inbound_handshake_comfirm(conn_context_t* tunnel, socket_ctx_t* socket) {
	if( !tunnel || !socket ){
		return;
	}
	xtrace(text_color_white, "do_s5_handshake_comfirm");
	char * data = socket->buf.base;
	if (socket->buf_len >= 20 && strncmp( data, "connect target is ok", 20) == 0) {
		xtrace(text_color_white, "do_s5_handshake_comfirm connect target is ok");
		tunnel->stage = tunnel_stage_streaming; // 进入数据转发阶段
		socket_tcp_write((uv_stream_t*)tunnel->input_tcp_handle,"\5\0\0\1\0\0\0\0\0\0", 10);		// 返回 SOCKS5 确认包
	}
}

/**
 * 释放 TLS (远程服务器) 连接资源回调
 * 优化: 缓冲区延迟释放到 do_stage_shutdown，避免重复释放
 */
void on_outbound_close_cb(uv_handle_t *handle) {
	conn_context_t *conn_ctx = (conn_context_t *)handle->data;
	// 优化: 缓冲区在 do_stage_shutdown 中统一释放
	free(conn_ctx->output_handle);
	conn_ctx->output_handle = NULL;
	conn_ctx->stage = tunnel_stage_shutdown;
	tunnel_dispatcher(conn_ctx, NULL);
}

/**
 * 新添加的 mbedTLS 接收超时回调函数 (实际只调用 my_mbedtls_recv)
 */
int my_mbedtls_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout) {
	//xtrace(text_color_red, "my_mbedtls_recv_timeout len:%d  to:%d", len, timeout);
	return my_mbedtls_recv(ctx, buf, len);
}

/**
 * tls 的读数据回调，当有新数据到达时调用 (来自远程服务器/VPS)
 * 优化: 1. 预分配缓冲区容量减少 realloc
 *       2. 复用 ssl_read_buffer 减少循环中的 malloc
 *       3. 移除不必要的 memset
 */
void on_outbound_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
	conn_context_t *conn_ctx = (conn_context_t *)stream->data;
	if ( nread < 0 ) {
		xtrace(text_color_red, "on_outbound_read_cb read:%zd err: %s", nread, uv_strerror((int)nread));
		uv_close((uv_handle_t*)stream, on_outbound_close_cb);
		if (buf->base) buffer_pool_release(buf->base);
		return;
	}
	conn_ctx->outbround_read_len += nread;

	// TLSinTLS处理: 如果处于 streaming 阶段且已标记为 TLS-in-TLS 转发
	if (conn_ctx->stage == tunnel_stage_streaming && conn_ctx->is_handle_tlsintls) {
		socket_ctx_t  ctx;
		ctx.buf = uv_buf_init(buf->base, (unsigned int)nread);
		ctx.buf_len = nread;
		ctx.handle = (uv_handle_t*)conn_ctx->output_handle;
		conn_ctx->output_read_buffer_len = 0;
		tunnel_dispatcher(conn_ctx, &ctx);
		if (buf->base) buffer_pool_release(buf->base);
		return;
	}

	// 优化: 使用预分配容量减少 realloc 次数
	size_t new_buffer_len = conn_ctx->output_read_buffer_len + nread;
	if (new_buffer_len > conn_ctx->output_read_buffer_capacity) {
		// 容量不足，扩容 (按2倍增长，最少 INITIAL_BUFFER_CAPACITY)
		size_t new_capacity = conn_ctx->output_read_buffer_capacity;
		if (new_capacity == 0) new_capacity = INITIAL_BUFFER_CAPACITY;
		while (new_capacity < new_buffer_len && new_capacity < MAX_BUFFER_CAPACITY) {
			new_capacity *= 2;
		}
		if (new_capacity < new_buffer_len) new_capacity = new_buffer_len;
		
		unsigned char *new_buffer = (unsigned char *)realloc(conn_ctx->output_read_buffer, new_capacity);
		if (new_buffer == NULL) {
			xtrace(text_color_red, "realloc failed");
			free(conn_ctx->output_read_buffer);
			conn_ctx->output_read_buffer = NULL;
			conn_ctx->output_read_buffer_len = 0;
			conn_ctx->output_read_buffer_capacity = 0;
			buffer_pool_release(buf->base);
			uv_close((uv_handle_t*)stream, on_outbound_close_cb);
			return;
		}
		conn_ctx->output_read_buffer = new_buffer;
		conn_ctx->output_read_buffer_capacity = new_capacity;
	}
	memcpy(conn_ctx->output_read_buffer + conn_ctx->output_read_buffer_len, buf->base, nread);
	conn_ctx->output_read_buffer_len = new_buffer_len;
	buffer_pool_release(buf->base);
	xtrace(text_color_white, "on_outbound_read_cb cache", conn_ctx->output_read_buffer, conn_ctx->output_read_buffer_len);

	//连接请求处理
	if (conn_ctx->stage == tunnel_stage_s5_connrequest) {
		int ret = mbedtls_ssl_handshake(&conn_ctx->ssl_ctx);
		if (ret == 0 ) {
			conn_ctx->stage = tunnel_stage_tls_handshaked;
			tunnel_dispatcher(conn_ctx, NULL);
		}else if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE ){
			// 继续等待数据
		}else {
			char error_buf[256];
			mbedtls_strerror(ret, error_buf, sizeof(error_buf));
			xtrace(text_color_red, "on_outbound_read_cb tunnel_stage_s5_connrequest mbedtls_ssl_handshake:%s (-0x%04x)", error_buf, -ret);
			// 握手失败，关闭连接触发资源清理
			uv_close((uv_handle_t*)stream, on_outbound_close_cb);
		}
		return;
	}

	//直到收到：connect target is ok.
	if (conn_ctx->stage == tunnel_stage_intent_target) {
		xtrace(text_color_white, "on_outbound_read_cb tunnel_stage_indicate_target");
		// 优化: 复用 ssl_read_buffer，避免每次分配
		if (!conn_ctx->ssl_read_buffer) {
			conn_ctx->ssl_read_buffer = (unsigned char*)malloc(FRAME_SIZE);
			conn_ctx->ssl_read_buffer_capacity = FRAME_SIZE;
		}
		int ret = mbedtls_ssl_read(&conn_ctx->ssl_ctx, conn_ctx->ssl_read_buffer, conn_ctx->ssl_read_buffer_capacity);
		if (ret > 0) {
			socket_ctx_t  ctx;
			ctx.buf = uv_buf_init((char*)conn_ctx->ssl_read_buffer, ret);
			ctx.buf_len = ret;
			ctx.handle = (uv_handle_t*)conn_ctx->output_handle;
			if (conn_ctx->input_udp_handle) {
				conn_ctx->stage = tunnel_stage_streaming;   //如果是UDP直接进入tunnel_stage_streaming流程
			}
			tunnel_dispatcher(conn_ctx, &ctx);
		}
		return;
	}

	//传输过程
	if (conn_ctx->stage == tunnel_stage_streaming) {
		// 优化: 复用 ssl_read_buffer，避免循环中重复分配
		if (!conn_ctx->ssl_read_buffer) {
			conn_ctx->ssl_read_buffer = (unsigned char*)malloc(FRAME_SIZE);
			conn_ctx->ssl_read_buffer_capacity = FRAME_SIZE;
		}
		int ret = 0;
		do {
			ret = mbedtls_ssl_read(&conn_ctx->ssl_ctx, conn_ctx->ssl_read_buffer, conn_ctx->ssl_read_buffer_capacity);
			if (ret > 0) {
				socket_ctx_t  ctx;
				ctx.buf = uv_buf_init((char*)conn_ctx->ssl_read_buffer, ret);
				ctx.buf_len = ret;
				ctx.handle = (uv_handle_t*)conn_ctx->output_handle;
				tunnel_dispatcher(conn_ctx, &ctx);
			}
		} while (ret > 0);
		return;
	}
}

/**
 * mbedTLS 随机数生成回调 (⚠️ 警告: 测试/示例代码，使用了硬编码的 13，非安全随机数)
 */
int my_mbedtls_ctr_drbg_random(void *p_rng, unsigned char *output, size_t output_len){
	mbedtls_ctr_drbg_context *ctx = (mbedtls_ctr_drbg_context *)p_rng;
	return mbedtls_ctr_drbg_random(ctx, output, output_len);
}

/**
 * mbedTLS Session Cache 获取回调(当前实现为返回 0，表示没有缓存)
 */
int my_cache_get(void *data, unsigned char const *session_id, size_t session_id_len, mbedtls_ssl_session *session) {
	// 在这里实现从缓存中获取会话数据的逻辑
	// 如果找到会话，返回 0；否则返回 -1 (这里直接返回0可能导致意想不到的行为，应该返回-1)
	return -1;
}

/**
 * mbedTLS Session Cache 设置回调 (当前实现为返回 0，表示成功)
 */
int my_cache_set(void *data, unsigned char const *session_id, size_t session_id_len, const mbedtls_ssl_session *session) {
	// 在这里实现将会话数据存储到缓存的逻辑
	// 返回 0 表示成功，非0表示失败
	return 0;
}

/**
 * TLS连接回调 (远程服务器连接成功)
 */
void on_outbound_connect_cb(uv_connect_t *req, int status) {
	conn_context_t *conn_ctx = (conn_context_t *)req->data;
    if (status != 0) {
        xtrace(text_color_red, "on_outbound_connect_cb failed: %s", uv_strerror(status));
        uv_close((uv_handle_t*)conn_ctx->output_handle, on_outbound_close_cb);
        free(req);
        return;
    }
	// 使用自带的测试证书 (CA 证书)
	mbedtls_x509_crt_init(&conn_ctx->cacert);
	int ret = mbedtls_x509_crt_parse(&conn_ctx->cacert, (const unsigned char *)c_mbedtls_test_cas_pem, strlen(c_mbedtls_test_cas_pem) + 1);
	if( ret != 0 ){
		xtrace(text_color_red, "mbedtls_x509_crt_parse failed: %d", ret);
		    mbedtls_x509_crt_free(&conn_ctx->cacert);  // 添加此行
		uv_close((uv_handle_t*)conn_ctx->output_handle, on_outbound_close_cb);
		free(req);
		return;
	}
	// 初始化 mbedTLS 上下文
	mbedtls_ssl_init(&conn_ctx->ssl_ctx);
	mbedtls_ssl_config_init(&conn_ctx->conf);
	mbedtls_ctr_drbg_init(&conn_ctx->ctr_drbg);
	mbedtls_entropy_init(&conn_ctx->entropy);
	// 播种 CTR_DRBG
	const char *pers = "ssl_client1";
	mbedtls_ctr_drbg_seed(&conn_ctx->ctr_drbg, mbedtls_entropy_func, &conn_ctx->entropy, (const unsigned char *)pers, strlen(pers));
	// 初始化 Session Cache
	mbedtls_ssl_conf_session_tickets(&conn_ctx->conf, MBEDTLS_SSL_SESSION_TICKETS_ENABLED); // 启用 session tickets
	mbedtls_ssl_cache_init(&conn_ctx->cache); // 初始化 session cache
	mbedtls_ssl_cache_set_max_entries(&conn_ctx->cache, 100); // 设置最大条目数
	mbedtls_ssl_conf_session_cache(&conn_ctx->conf, (void*)&conn_ctx->cache, my_cache_get, my_cache_set); // 设置 session cache 的回调函数
	// 设置默认配置为客户端模式
	mbedtls_ssl_config_defaults(&conn_ctx->conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	mbedtls_ssl_conf_authmode(&conn_ctx->conf, MBEDTLS_SSL_VERIFY_NONE); // **不验证**服务器证书 (MBEDTLS_SSL_VERIFY_NONE)
	mbedtls_ssl_conf_ca_chain(&conn_ctx->conf, &conn_ctx->cacert, NULL); // 设置 CA 证书链
	mbedtls_ssl_conf_rng(&conn_ctx->conf, my_mbedtls_ctr_drbg_random, &conn_ctx->ctr_drbg);  // 设置随机数生成器
	mbedtls_ssl_setup(&conn_ctx->ssl_ctx, &conn_ctx->conf);
	mbedtls_ssl_set_hostname(&conn_ctx->ssl_ctx, conn_ctx->state->my_config->fake_sni); // 设置 SNI 主机名
	mbedtls_ssl_set_bio(&conn_ctx->ssl_ctx, conn_ctx, my_mbedtls_send, my_mbedtls_recv, my_mbedtls_recv_timeout);
	// 标记 mbedTLS 资源已初始化，用于 do_stage_shutdown 安全释放
	conn_ctx->is_mbedtls_initialized = true;
	// 设置 Session ID，用于自定义的身份验证/会话重用机制
	struct session_id sid;
	create_session_id(&sid, ( ATOMIC_LOAD_BOOL(g_had_verified) )?1:0, conn_ctx->state->my_authinfo_md5); // 第一次连接使用 '0' 标记
	//mbedtls_ssl_set_sessionid(&conn_ctx->ssl_ctx, (unsigned char*)&sid);
	// 启动读事件，驱动 TLS 握手 (第一次尝试握手)
	ret = mbedtls_ssl_handshake(&conn_ctx->ssl_ctx);
	if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
		uv_read_start((uv_stream_t *)conn_ctx->output_handle, alloc_buffer_cb, on_outbound_read_cb); // 开始读取远程数据
	}else if (ret != 0) {
		char error_buf[256];
		mbedtls_strerror(ret, error_buf, sizeof(error_buf));
		xtrace(text_color_red, "on_outbound_connect_cb mbedtls_ssl_handshake:%s (-0x%04x)", error_buf, -ret);
		// mbedtls 已初始化，通过 close 回调链触发完整清理
		uv_close((uv_handle_t*)conn_ctx->output_handle, on_outbound_close_cb);
		free(req);
		return;	
	}

	// 如果是UDP通信，返回S5目标连接确认
	if ( conn_ctx->input_udp_handle ) {
		struct sockaddr_in udp_bound_addr;
		int bound_addr_len = sizeof(udp_bound_addr);
		uv_udp_getsockname(conn_ctx->input_udp_handle, (struct sockaddr*)&udp_bound_addr, &bound_addr_len);
		uint16_t src_port = htons(udp_bound_addr.sin_port);
		uint8_t data[] = "\x05\x00\x00\x01\x7F\x00\x00\x01\x00\x00";
		memcpy(&data[8], &src_port,2);
		uv_write_t* write_req = (uv_write_t*)malloc(sizeof(uv_write_t));
		write_req->data = (char*)malloc(10);
		memcpy(write_req->data, data, 10);
		uv_buf_t  buf = uv_buf_init(write_req->data, 10);
		int ret = uv_write(write_req, (uv_stream_t*)conn_ctx->input_tcp_handle, &buf, 1, socket_write_done_cb);
		if (ret != 0) {
			xtrace(text_color_red, "on_outbound_connect_cb uv_write failed: %s(%d)", uv_strerror(ret), ret);
			uv_close((uv_handle_t*)conn_ctx->output_handle, on_outbound_close_cb);
			free(write_req->data);
			free(write_req);
			return;
		}
		xtrace(text_color_white, "socket_tcp_write len:10 ret:%d", ret);
	}
	free(req);
}

/**
* mbedTLS 的发送回调函数，将数据写入 libuv 流
* 优化: 使用 malloc 代替 calloc
* 优化: 对于小数据包，先尝试 uv_try_write
*/
int my_mbedtls_send(void *ctx, const unsigned char *buf, size_t len) {
	htrace(text_color_white, "my_mbedtls_send to client", (char*)buf, len);
	conn_context_t *conn_ctx = (conn_context_t *)ctx;
	if ( conn_ctx->output_handle) {
		return socket_tcp_write((uv_stream_t*)conn_ctx->output_handle, buf, len);
	}
	return MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}

/**
 * 将 SSL 缓存数据全部发送完成 (循环调用 mbedtls_ssl_write 直到数据发完)
 * 优化: 移除不必要的错误字符串转换
 */
int mbedtls_ssl_write_all(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t len) {
	int ret = 0;
	size_t sent = 0;
	htrace(text_color_white, "mbedtls_ssl_write_all", (char*)buf, len);
	do {
		ret = mbedtls_ssl_write(ssl, buf + sent, len - sent);
		if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
			continue; // 需要等待写入就绪
		}
		if (ret < 0) {
			xtrace(text_color_red, "mbedtls_ssl_write_all ret:%d", ret);
			break; // 写入失败
		}
		sent += ret;
	} while (sent < len);
	return (int)sent;
}

/**
 * 将ssl缓存数据全部发送完成
 * 优化: 减少调试输出
 */
int application_data_forword(void *ctx, const unsigned char *buf, size_t len) {
	conn_context_t *conn_ctx = (conn_context_t *)ctx;
	int ret = 0;
	size_t sent = 0;
	do {
		ret = mbedtls_ssl_write(&conn_ctx->ssl_ctx, buf + sent, len - sent);
		xtrace(text_color_white, "application_data_forword ret:%d len:%zu", ret, len);
		if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
			continue;
		}
		if (ret < 0) {
			xtrace(text_color_red, "application_data_forword ret:%d", ret);
			break;
		}
		sent += ret;
	} while (sent < len);
	return (int)sent;
}

/**
 * mbedTLS 的接收回调函数，从我们自己的缓存中读取数据
 * 优化: 保留预分配的缓冲区容量，只重置长度和偏移量
 */
int my_mbedtls_recv(void *ctx, unsigned char *buf, size_t len) {
	conn_context_t *conn_ctx = (conn_context_t *)ctx;
	// 检查缓存中是否有数据可读
	size_t available_data = conn_ctx->output_read_buffer_len - conn_ctx->output_read_buffer_offset;
	if (available_data == 0) {
		// 缓存为空，需要更多数据
		return MBEDTLS_ERR_SSL_WANT_READ;
	}
	// 确定本次要读取的字节数, 从缓存中拷贝数据到 mbedTLS 提供的缓冲区，更新偏移量
	size_t bytes_to_read = (len < available_data) ? len : available_data;
	memcpy(buf, conn_ctx->output_read_buffer + conn_ctx->output_read_buffer_offset, bytes_to_read);
	conn_ctx->output_read_buffer_offset += bytes_to_read;
	// 优化: 如果所有缓存的数据都已消费，只重置长度和偏移量，保留容量
	if (conn_ctx->output_read_buffer_offset == conn_ctx->output_read_buffer_len) {
		// 不释放缓冲区，只重置长度和偏移量，下次可以复用
		conn_ctx->output_read_buffer_len = 0;
		conn_ctx->output_read_buffer_offset = 0;
	}
	return (int)bytes_to_read;
}

/**
 * 握手后第一个数据包发送 (目标地址信息 + 身份验证信息) (阶段 2)
 * 优化: 减少调试输出，减少 memset 使用
 */
void do_tls_addressinfo_data(conn_context_t* tunnel, socket_ctx_t* socket) {
	xtrace(text_color_blue, "do_tls_addressinfo_data indicate target");
	if ( tunnel->is_had_intent_target  ||  tunnel->target_address_pkg.len == 0 ) {
		return;
	}
	// 发送目标地址包后，等待服务器返回 SOCKS5 确认
	tunnel->stage = tunnel_stage_intent_target;
	tunnel->is_had_intent_target = true;
	// 已验证，只发送目标地址数据包
	if ( ATOMIC_LOAD_BOOL(g_had_verified) ) {
		size_t padding_len = rand() % 0x80;
		size_t data_len = tunnel->target_address_pkg.len + padding_len;
		char * data = (char*)malloc(data_len);
		memcpy(data, tunnel->target_address_pkg.base, tunnel->target_address_pkg.len);
		// 优化: 只清零填充部分
		if (padding_len > 0) {
			memset(data + tunnel->target_address_pkg.len, 0x00, padding_len);
		}
		application_data_forword(tunnel, (const unsigned char *)data, data_len);
		free(data);
		return;
	}
	// 首次连接，构造包含目标地址包和身份验证信息的完整数据包
	size_t padding_len = rand() % 0x80;
	size_t data_len = tunnel->target_address_pkg.len + sizeof(auth_info_t) + padding_len;
	char * data = (char*)malloc( data_len );
	memcpy(data, tunnel->target_address_pkg.base, tunnel->target_address_pkg.len);
	struct auth_info authinfo;
	memset(&authinfo, 0x00, sizeof(auth_info_t));
	authinfo.app_type =tunnel->state->my_config->app_type;
	authinfo.user_id = tunnel->state->my_config->user_id;
	string_to_uuid(tunnel->state->my_config->user_name, authinfo.user_name);
	string_to_uuid(tunnel->state->my_config->user_cipher, authinfo.user_cipher);
	memcpy(data + tunnel->target_address_pkg.len, (void*)&authinfo, sizeof(auth_info_t));
	// 优化: 只清零填充部分
	if (padding_len > 0) {
		memset(data + tunnel->target_address_pkg.len + sizeof(auth_info_t), 0x00, padding_len);
	}
	application_data_forword(tunnel, (const unsigned char *)data, data_len);
	ATOMIC_STORE_BOOL(g_had_verified, 1);// 标记已验证
	if (tunnel->state->feedback_state) {
		tunnel->state->feedback_state(tunnel->state->ptr, tunnel->state, "connect ok.");
	}
	free(data);
}

/**
 * tls 数据传输，包括 IN/OUT (阶段 4)
 * 优化: 减少调试输出，使用 malloc 代替 calloc
 */
void do_data_forword(conn_context_t* tunnel, socket_ctx_t* socket) {
	uint8_t* data = (uint8_t*)socket->buf.base;
	size_t size = (size_t)socket->buf_len;
#ifdef _WIN32
	if ( tunnel->output_handle && ((uv_tcp_t*)(socket->handle))->socket == tunnel->output_handle->socket) {
#else
	if ( tunnel->output_handle && socket->handle == (uv_handle_t*)tunnel->output_handle) {
#endif
		//UDP数据转发
		if (tunnel->input_udp_handle) {
			char * buffer = (char*)malloc(size + 10);	
			buffer[0] = 0x00;  /* RSV */
			buffer[1] = 0x00;  /* RSV */
			buffer[2] = 0x00;  /* FRAG */
			buffer[3] = 0x01;  /* IPv4 */
			struct sockaddr_in * sain = (struct sockaddr_in *)&tunnel->s5_dst_addr;
			memcpy(&buffer[4], &sain->sin_addr.s_addr, 4);
			buffer[8] = (ntohs(sain->sin_port) >> 8) & 0xFF;
			buffer[9] = ntohs(sain->sin_port) & 0xFF;
			memcpy(&buffer[10], data, size);
			int ret = socket_udp_write((uv_udp_t*)tunnel->input_udp_handle, &tunnel->s5_src_addr, buffer, size + 10);
			xtrace(text_color_white, "do_data_forword UDP send ret:%s(%d)", uv_strerror(ret), ret);
			free(buffer);
			return;
		}
		//TCP数据转发
		if (tunnel->input_tcp_handle) {
			int ret = socket_tcp_write((uv_stream_t*)tunnel->input_tcp_handle, data, size);
			xtrace(text_color_white, "do_data_forword TCP send ret:%s(%d)", uv_strerror(ret), ret);
			return;
		}
	}
#ifdef _WIN32
	else if ( tunnel->input_tcp_handle && ((uv_tcp_t*)(socket->handle))->socket == tunnel->input_tcp_handle->socket) {
#else
	else if ( tunnel->input_tcp_handle && socket->handle == (uv_handle_t*)tunnel->input_tcp_handle) {
#endif
		if (tunnel->output_handle) {
			application_data_forword( tunnel, data, size);
			return;
		}
	}
	htrace(text_color_white, "do_data_forword handless", data, size);
}

/**
 * 释放 SOCKS5 (客户端) 连接资源回调
 */
void on_udp_close_cb(uv_handle_t *handle) {
	//xtrace(text_color_white, "on_inbound_close_cb handle");
	conn_context_t *conn_ctx = (conn_context_t *)handle->data;
	free(conn_ctx->input_udp_handle);
	conn_ctx->input_udp_handle = NULL;
}

/**
 * udp 发送至S5回调
 */
void uv_inbround_udp_send_cb(uv_udp_send_t* req, int status) {
	if (req->data) {
		free(req->data);
	}
	free(req);
}

/**
 * S5 UDP接收数据
 * 优化: 使用内存池
 */
void on_inbround_udp_recv(uv_udp_t* handle, ssize_t nread, const uv_buf_t* rcvbuf, const struct sockaddr* addr, unsigned flags) {
	if ( nread <=  0 ) {
		if (rcvbuf->base) buffer_pool_release(rcvbuf->base);
		return;
	}
	htrace(text_color_white, "on_udp_recv", rcvbuf->base, nread);
	conn_context_t *conn_ctx = (conn_context_t *)handle->data;
	memcpy(&conn_ctx->s5_src_addr, addr, sizeof(const struct sockaddr));
	if( conn_ctx->target_address_pkg.base == NULL ){  	//如果是首次接收数据包
		//首包，需要解析目标地址，缓存数据包
		size_t frag;
		size_t size;
		struct socks5_address tag_addr;
		memset(&tag_addr, 0x00, sizeof(struct socks5_address));
		s5_parse_upd_package(rcvbuf->base, nread, &tag_addr, &frag, &size);
		conn_ctx->target_address_pkg = uv_buf_init((char*)malloc(nread), (unsigned int)nread);
		memcpy(conn_ctx->target_address_pkg.base, rcvbuf->base, nread);
		conn_ctx->target_address_pkg.len = (unsigned int)nread;
		//目标地址信息
		char* tmp = socks5_address_to_string(&tag_addr, &malloc, false);
		if( tmp ){
			xtrace(text_color_white, "socks5_address_to_string %s:%d", tmp, tag_addr.port);
			uv_ip4_addr(tmp, tag_addr.port, (struct sockaddr_in*)&conn_ctx->s5_dst_addr);
			free(tmp);
		}
	}else{
		//应用数据转发
		application_data_forword(conn_ctx, (const unsigned char*)rcvbuf->base, nread);
	}
	buffer_pool_release(rcvbuf->base);
	return;
}

/**
 * 关闭通道，只有 input 和 output 都断开后才释放通道 (阶段 5)
 */
void do_stage_shutdown(conn_context_t* tunnel) {
	if (tunnel->input_tcp_handle) {
		xtrace(text_color_white, "do_stage_shutdown to close tcp_input");
		if (!uv_is_closing((uv_handle_t*)tunnel->input_tcp_handle)) {
			uv_close((uv_handle_t*)tunnel->input_tcp_handle, on_inbound_close_cb);
		}
	}
	else if (tunnel->input_udp_handle) {
		xtrace(text_color_white, "do_stage_shutdown to close udp_input");
		if (!uv_is_closing((uv_handle_t*)tunnel->input_udp_handle)) {
			uv_close((uv_handle_t*)tunnel->input_udp_handle, on_inbound_close_cb);
		}
	}
	else if (tunnel->output_handle) {
		xtrace(text_color_white, "do_stage_shutdown to close output");
		if (!uv_is_closing((uv_handle_t*)tunnel->output_handle)) {
			uv_close((uv_handle_t*)tunnel->output_handle, on_outbound_close_cb);
		}
	}
	// 只有 input 和 output 都为 NULL 时，才释放 conn_context
	if (tunnel->input_tcp_handle == NULL && tunnel->output_handle == NULL && tunnel->input_udp_handle == NULL) {
		ATOMIC_DEC(g_conn_context_count);
		xtrace(text_color_white, "do_stage_shutdown flow:%zu conn count:%ld", tunnel->inbround_read_len, g_conn_context_count);
		// 只有在 mbedTLS 资源已初始化时才释放，避免释放未初始化的结构体
		if (tunnel->is_mbedtls_initialized) {
			mbedtls_ssl_free(&tunnel->ssl_ctx);
			mbedtls_ssl_config_free(&tunnel->conf);
			mbedtls_ctr_drbg_free(&tunnel->ctr_drbg);
			mbedtls_entropy_free(&tunnel->entropy);
			mbedtls_ssl_cache_free(&tunnel->cache);
			mbedtls_x509_crt_free(&tunnel->cacert);
		}
		if( tunnel->target_address_pkg.base ){
			free(tunnel->target_address_pkg.base);
			tunnel->target_address_pkg.base = NULL;
			tunnel->target_address_pkg.len = 0;	
		}
		// 优化: 释放复用的缓冲区
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
 * dispath (隧道状态机调度函数)
 */
static void tunnel_dispatcher(conn_context_t* tunnel, socket_ctx_t* socket) {
	switch (tunnel->stage) {
	case tunnel_stage_s5_handshake: // 0: SOCKS5 握手 (Hello)
    	do_inbound_handshake(tunnel, socket);
		break;

	case tunnel_stage_s5_connrequest: // 1: SOCKS5 连接请求 (目标地址)
		do_inbound_handshake_connvps(tunnel, socket);
		break;

	case tunnel_stage_tls_handshaked: // 2: TLS 握手完成
		do_tls_addressinfo_data(tunnel, socket);
		break;

	case tunnel_stage_intent_target: // 3: 发送目标地址后，等待 VPS 确认
		do_inbound_handshake_comfirm(tunnel, socket);
		break;

	case tunnel_stage_streaming: // 4: 数据转发
		do_data_forword(tunnel, socket);
		break;

	case tunnel_stage_shutdown: // 5: 关闭连接/资源清理
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
	uv_walk(uv_default_loop(), close_walk_cb, NULL);
}

/**
 * reality 客户端启动导出函数
 */
int reality_run_loop_begin(struct configure *cf, void(*feedback_state)(void *p, struct reality_client_state *state, const char* info), void *p) {
	xtrace(text_color_white, "inno reality - client (optimized)");
	struct reality_client_state * state = (struct reality_client_state *) calloc(1, sizeof(*state));
	state->feedback_state = feedback_state;
	state->ptr = p;
	srand((unsigned int)time(NULL));
	ATOMIC_STORE_BOOL(g_had_verified, 0);
	buffer_pool_init(); 	// 优化: 初始化内存池
	// 初始化身份验证信息并计算 MD5
	state->my_authinfo.app_type = cf->app_type;
	state->my_authinfo.user_id = cf->user_id;
	string_to_uuid(cf->user_name, state->my_authinfo.user_name);
	string_to_uuid(cf->user_cipher, state->my_authinfo.user_cipher);
	mbedtls_md5((uint8_t *)&state->my_authinfo, sizeof(struct auth_info), (uint8_t *)state->my_authinfo_md5);

	uv_loop_t *loop = uv_default_loop();
	//安装 signal handler for Ctrl+C
	uv_signal_init(loop, &state->signal_handle);
	uv_signal_start(&state->signal_handle, on_signal, SIGINT);
	//开启服务
	uv_tcp_t   server_socket;
	server_socket.data = (void*)state;
	struct sockaddr_in addr;
	uv_tcp_init(loop, &server_socket);
	uv_tcp_nodelay(&server_socket, 1);
	uv_ip4_addr(state->my_config->local_host, state->my_config->local_port, &addr);
	uv_tcp_bind(&server_socket, (const struct sockaddr*)&addr, 0);
	int r = uv_listen((uv_stream_t*)&server_socket, 1024, on_inbound_listen_cb);
	xtrace(text_color_white, "start socks5 server listening on:%d error:%s", state->my_config->local_port, uv_strerror(r));
	xtrace(text_color_white, "Press Ctrl+C to stop");
	uv_run(loop, UV_RUN_DEFAULT);
	//正常退出时显式关闭 server_socket，避免 uv_loop_close(UV_EBUSY)
	if (!uv_is_closing((uv_handle_t*)&server_socket)) {
		uv_close((uv_handle_t*)&server_socket, NULL);
		uv_run(loop, UV_RUN_DEFAULT);  // 跑完关闭
	}
	ATOMIC_STORE_BOOL(g_had_verified, 0);
	uv_loop_close(loop);
	buffer_pool_destroy();    // 优化: 销毁内存池
	configure_destroy(state->my_config);
	xtrace(text_color_white, "safe exit.\n");
	exit(0);
	return 0;
}

/**
 * reality 客户端关闭导出函数
 */
void reality_run_loop_shutdown(struct reality_client_state* state) {
	uv_signal_stop(&state->signal_handle);
	uv_close((uv_handle_t*)&state->signal_handle, NULL);
	xtrace(text_color_white, "terminated.\n");
}

/**
 * main 主函数
 */
int main(int argc, char * argv[]) {
	xtrace(text_color_white, "inno reality - client (optimized)");
	struct reality_client_state * state = (struct reality_client_state *) calloc(1, sizeof(*state));
	srand((unsigned int)time(NULL));
	buffer_pool_init(); 	// 优化: 初始化内存池
	state->my_config = configure_create(argc, argv); // 加载配置
	// 初始化身份验证信息并计算 MD5
	state->my_authinfo.app_type = state->my_config->app_type;
	state->my_authinfo.user_id = state->my_config->user_id;
	string_to_uuid(state->my_config->user_name, state->my_authinfo.user_name);
	string_to_uuid(state->my_config->user_cipher, state->my_authinfo.user_cipher);
	mbedtls_md5((uint8_t *)&state->my_authinfo, sizeof(struct auth_info), (uint8_t *)state->my_authinfo_md5);
	uv_loop_t *loop = uv_default_loop();
	//安装 signal handler for Ctrl+C
	uv_signal_init(loop, &state->signal_handle);
	uv_signal_start(&state->signal_handle, on_signal, SIGINT);
	//开启服务
	uv_tcp_t   server_socket;
	server_socket.data = (void*)state;
	struct sockaddr_in addr;
	uv_tcp_init(loop, &server_socket);
	uv_tcp_nodelay(&server_socket, 1);
	uv_ip4_addr(state->my_config->local_host, state->my_config->local_port, &addr);
	uv_tcp_bind(&server_socket, (const struct sockaddr*)&addr, 0);
	int r = uv_listen((uv_stream_t*)&server_socket, 1024, on_inbound_listen_cb);
	xtrace(text_color_white, "start socks5 server listening on:%d error:%s", state->my_config->local_port, uv_strerror(r));
	xtrace(text_color_white, "Press Ctrl+C to stop");
	uv_run(loop, UV_RUN_DEFAULT);
	//正常退出时显式关闭 server_socket，避免 uv_loop_close(UV_EBUSY)
	if (!uv_is_closing((uv_handle_t*)&server_socket)) {
		uv_close((uv_handle_t*)&server_socket, NULL);
		uv_run(loop, UV_RUN_DEFAULT);  // 跑完关闭
	}
	uv_loop_close(loop);
	buffer_pool_destroy();    // 优化: 销毁内存池
	configure_destroy(state->my_config);
	xtrace(text_color_white, "safe exit.\n");
	exit(0);
	return 0;
}
