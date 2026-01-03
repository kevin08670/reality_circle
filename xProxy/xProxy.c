// xProxy.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <uv.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>
#include <mbedtls/ssl_ticket.h>
#include <mbedtls/ssl_cache.h>
#include <mbedtls/platform.h>
#ifdef WIN32
#include <process.h >
#endif
#include "../s5.h"
#include "../sockaddr_universal.h"
#include "../text_in_color.h"
#include "../configure.h"
#include "addr_mgr.h"
#include "user_mgr.h"
#include "cert_mgr.h"

//#define PROBE_HANDLE           // 开启 **探测流程** 开发 (用于抵御指纹识别/探测)
//#define TLSINTLS_HANDLE      // 开启 **TlsinTls 处理**, 只有 TLS1.3 才能开启 (但代码中强制限制为TLS1.2)

/* Session states. */
#define TUNNEL_STAGE_MAP(V)   \
    V( 0, tunnel_stage_tls_clientHello, "tunnel_stage_tls_clientHello")  \
	V( 1, tunnel_stage_tls_stealhandle, "tunnel_stage_tls_stealhandle")  \
    V( 2, tunnel_stage_tls_handshaked,  "tunnel_stage_tls_handshaked")   \
    V( 3, tunnel_stage_tls_streaming, "tunnel_stage_tls_streaming")  \
    V( 4, tunnel_stage_probe_streaming, "tunnel_stage_probe_streaming")  \
    V( 5, tunnel_stage_shutdown, "tunnel_stage_shutdown")  \

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
	int result;
	uv_tcp_t * handle;
	uv_timer_t timer_handle;
	union uv_any_req req;
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
	uv_tcp_t * output_handle;                        //输出 / 转发层
	char *output_read_buffer;
	size_t output_read_buffer_len;
	size_t output_read_buffer_offset;
	uv_tcp_t * steal_handle;                           //窃取/回落层
	mbedtls_ssl_context ssl_ctx;
	struct uv_buf_t target_address_pkg;
	union sockaddr_universal target_addr;
	char probe_sni[256];
	unsigned char session_id[32];
	unsigned char server_hello[65505];
	size_t client_hello_len;
	size_t server_hello_len;
	bool is_handle_tlsintls;               //是否启用 TLS-in-TLS 转发 (直接转发 TLS 记录)
	bool is_clientHello;                     //是否为ClientHello
	bool is_verified;
} conn_context_t;


//函数定义
static void tunnel_dispatcher(conn_context_t* tunnel, socket_ctx_t* socket);
void on_outbround_listen_cb(uv_connect_t *req, int status);
void do_stage_shutdown(conn_context_t* tunnel, socket_ctx_t* socket);
void do_probe_catch(conn_context_t* tunnel, socket_ctx_t* socket);
void do_data_forword(conn_context_t* tunnel, socket_ctx_t* socket);
int mbedtls_ssl_write_all(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t len);
void on_outbround_close_cb(uv_handle_t *handle);
void on_steal_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf);
void on_steal_listen_cb(uv_connect_t *req, int status);
void on_steal_close_cb(uv_handle_t *handle);

//成员定义
static unsigned int conn_channel_count = 0;
static struct ip_addr_cache * resolved_ip_cache = NULL;
static struct usermgr * my_usermgr = NULL;
static struct certmgr * my_certmgr = NULL;
static struct shcrtmgr * my_shcrtmgr = NULL;

struct configure * my_config = NULL;
mbedtls_ssl_config conf;
mbedtls_x509_crt cacert;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_pk_context pkey;

// socket 写入完成回调
static void uv_socket_write_done_cb(uv_write_t* req, int status) {
	if (req->data) {
		free(req->data);
	}
	free(req);
}

// 写入数据到指定 socket
void socket_ctx_write(struct socket_ctx* socket, const void* data, size_t len) {
	trace("socket_ctx_write");
	uv_write_t* req = (uv_write_t*)calloc(1, sizeof(uv_write_t));
	req->data = (char*)malloc(len);
	memcpy(req->data, data, len);
	uv_buf_t buf = uv_buf_init(req->data, (unsigned int)len);
	int ret = uv_write(req, (uv_stream_t*)socket->handle, &buf, 1, uv_socket_write_done_cb);
	trace("socket_ctx_write  ret:%d", ret);
}

// 缓冲区分配回调 (libuv 读操作前调用)
void alloc_buffer_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
	buf->base = (char *)malloc(suggested_size);
	buf->len = suggested_size;
	(void)handle;
}

////////////////////////////////////////////// client (input) /////////////////////////////////////////////////////////////////////

// 释放客户端 (TLS) 连接资源回调
void on_tls_close_cb(uv_handle_t *handle) {
	trace("on_tls_close_cb handle flags:%d", handle->flags);
	conn_context_t *conn_ctx = (conn_context_t *)handle->data;
	// 释放客户端读取缓冲区
	if (conn_ctx->input_read_buffer) {
		free(conn_ctx->input_read_buffer);
		conn_ctx->input_read_buffer = NULL;
	}
	free(conn_ctx->input_handle);
	// 切换到关闭阶段，触发资源清理
	conn_ctx->input_handle = NULL;
	conn_ctx->stage = tunnel_stage_shutdown;
	tunnel_dispatcher(conn_ctx, NULL);
}

// mbedTLS 的发送回调函数，将数据写入 libuv 流
int my_mbedtls_send(void *ctx, const unsigned char *buf, size_t len) {
	//hex_trace("my_mbedtls_send to client", (char*)buf, len);
	conn_context_t *conn_ctx = (conn_context_t *)ctx;
	//if (conn_ctx->input_handle) {
	//	//如果是server_hello 将要用缓存的目标服务器的server_hello
	//	if (buf[0] == 0x16 && buf[5] == 0x02) {
	//		trace("target server hello.");
	//		char * hello_data = NULL;
	//		size_t hello_len = 0;
	//		get_clientHello(my_certmgr, "abc", &hello_data, &hello_len);
	//		uv_write_t* req = (uv_write_t*)calloc(1, sizeof(uv_write_t));
	//		req->data = (char*)malloc(hello_len);
	//		memcpy(req->data, hello_data, hello_len);
	//		memcpy( (char*)req->data + 44 , buf+44, 32);
	//		uv_buf_t buf = uv_buf_init(req->data, (unsigned int)hello_len);
	//		uv_write(req, (uv_stream_t *)conn_ctx->input_handle, &buf, 1, uv_socket_write_done_cb);
	//	}else {
	//		uv_write_t* req = (uv_write_t*)calloc(1, sizeof(uv_write_t));
	//		req->data = (char*)malloc(len);
	//		memcpy(req->data, buf, len);
	//		uv_buf_t buf = uv_buf_init(req->data, (unsigned int)len);
	//		uv_write(req, (uv_stream_t *)conn_ctx->input_handle, &buf, 1, uv_socket_write_done_cb);
	//	}
	//}
	return (int)len;
}

// mbedTLS 的接收回调函数，从我们自己的缓存中读取数据
int my_mbedtls_recv(void *ctx, unsigned char *buf, size_t len) {
	if ( !buf  || len <=0  ) {
		trace("my_mbedtls_recv emtpy");
		return -1;
	}
	trace("my_mbedtls_recv 1  size:%d", len);
	conn_context_t *conn_ctx = (conn_context_t *)ctx;
	// 检查缓存中是否有数据可读
	size_t available_data = conn_ctx->input_read_buffer_len - conn_ctx->input_read_buffer_offset;
	if (available_data == 0) {
		// 关键点: 没有数据可用，返回 WANT_READ 告诉 mbedTLS 等待,这样 mbedtls 就不会阻塞，而是依赖 libuv 的异步读事件
		trace("my_mbedtls_recv MBEDTLS_ERR_SSL_WANT_READ");
		return MBEDTLS_ERR_SSL_WANT_READ;
	}
	// 确定本次要读取的字节数// 从缓存中拷贝数据到 mbedTLS 提供的缓冲区，更新偏移量
	size_t bytes_to_read = (len < available_data) ? len : available_data;
	memcpy(buf, conn_ctx->input_read_buffer + conn_ctx->input_read_buffer_offset, bytes_to_read);
	conn_ctx->input_read_buffer_offset += bytes_to_read;
	// 如果所有缓存的数据都已消费，则重置缓存
	if (conn_ctx->input_read_buffer_offset == conn_ctx->input_read_buffer_len) {
		hex_trace("my_mbedtls_recv", conn_ctx->input_read_buffer, conn_ctx->input_read_buffer_len);
		free(conn_ctx->input_read_buffer);
		conn_ctx->input_read_buffer = NULL;
		conn_ctx->input_read_buffer_len = 0;
		conn_ctx->input_read_buffer_offset = 0;
	}
	return (int)bytes_to_read;
}

// mbedTLS 接收超时回调 (在 libuv 模型中，此函数和 my_mbedtls_recv 效果相同)
int my_mbedtls_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout) {
	trace("my_mbedtls_recv_timeout len:%d  to:%d", len, timeout);
	(void)timeout;
	return  my_mbedtls_recv(ctx, buf, len);
}

//Application 数据发送
int fake_mbedtls_send(void *ctx, const unsigned char *buf, size_t len) {
	conn_context_t *conn_ctx = (conn_context_t *)ctx;
#ifdef FAKE_APPLICATION
	char *  app_data = (char*)malloc(len + 5);
	app_data[0] = 0x17;
	app_data[1] = 0x03;
	app_data[2] = 0x03;
	app_data[3] = (len >> 8) & 0xFF;
	app_data[4] = len & 0xFF;
	memcpy(app_data + 5, buf, len);
	uv_write_t *req = (uv_write_t *)malloc(sizeof(uv_write_t));
	req->data = (void*)app_data;
	uv_buf_t write_buf = uv_buf_init(app_data, len + 5);
	int ret = uv_write(req, (uv_stream_t *)conn_ctx->input_handle, &write_buf, 1, uv_socket_write_done_cb);
	hex_trace("fake_mbedtls_send", app_data, len + 5);
#else
	char *  app_data = (char*)malloc(len);
	memcpy(app_data, buf, len);
	uv_write_t *req = (uv_write_t *)malloc(sizeof(uv_write_t));
	req->data = (void*)app_data;
	uv_buf_t write_buf = uv_buf_init(app_data, len);
	int ret = uv_write(req, (uv_stream_t *)conn_ctx->input_handle, &write_buf, 1, uv_socket_write_done_cb);
	hex_trace("fake_mbedtls_send", app_data, len);
#endif
	return (int)len; // 必须返回成功写入的字节数
}

/*
*==读取探测服务器返回数据==
*该阶段已进入tunnel_stage_origin_streaming状态，直接透明转发.
*/
void on_probe_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
	conn_context_t *conn_ctx = (conn_context_t *)stream->data;
	if (nread > 0) {
		socket_ctx_t  ctx;
		ctx.buf = *buf;
		ctx.buf_len = nread;
		ctx.handle = conn_ctx->output_handle;
		hex_trace("on_probe_read_cb form target", buf->base, nread);
		tunnel_dispatcher(conn_ctx, &ctx);
	}
	else {
		trace("on_probe_read_cb [%d] to close", nread);
		uv_close((uv_handle_t*)stream, on_outbround_close_cb);
	}
}

/*
*==监听探测服务器==
*待连接成功后，直接将clientHello数据包发送至探测服务器
*/
void on_probe_listen_cb(uv_connect_t *req, int status) {
	if (status < 0) {
		trace("on_target_listen_cb  连接错误: %s", uv_strerror(status));
		return;
	}
	trace("on_target_listen_cb create new connect.");
	conn_context_t * tunnel = (conn_context_t *)req->data;
	uv_read_start((uv_stream_t *)tunnel->output_handle, alloc_buffer_cb, on_probe_read_cb);
	char *  data = tunnel->ssl_ctx.private_in_hdr;
	size_t  data_len = tunnel->ssl_ctx.private_in_msglen;
	mbedtls_ssl_write_all(&tunnel->ssl_ctx, (const unsigned char *)data, data_len);
	tunnel->stage = tunnel_stage_probe_streaming;
}

/*
*==探测域名解析回调==
*成功返回将直接连接探测服务器
*/
static void get_probe_addrinfo_done_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs) {
	if (status != 0 || addrs == NULL || !req || !req->data) {
		return;
	}
	//域名解析地址 + from socks5 addr:port
	char * domain = (char*)req->reserved[0];
	conn_context_t *tunnel = (conn_context_t *)req->data;
	struct sockaddr_in dest = *(const struct sockaddr_in*)addrs->ai_addr;
	dest.sin_port = htons(tunnel->target_addr.addr4.sin_port);
	if (ip_addr_cache_is_address_exist(resolved_ip_cache, domain) == false) {
		trace("getaddrinfo_done_cb push cache domain:%s ip:%s:%d", domain, inet_ntoa(dest.sin_addr), tunnel->target_addr.addr4.sin_port);
		union sockaddr_universal * address = (union sockaddr_universal*) malloc(sizeof(union sockaddr_universal));
		address->addr4.sin_addr = dest.sin_addr;
		address->addr4.sin_port = dest.sin_port;
		ip_addr_cache_add_address(resolved_ip_cache, domain, address);
	}
	//连接到目标服务器
	tunnel->output_handle = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
	uv_tcp_init(uv_default_loop(), tunnel->output_handle);
	tunnel->output_handle->data = (void*)tunnel;
	uv_connect_t *conn_req = (uv_connect_t *)malloc(sizeof(uv_connect_t));
	conn_req->data = (void*)tunnel;
	uv_tcp_connect(conn_req, tunnel->output_handle, (const struct sockaddr *)&dest, on_probe_listen_cb);
	uv_freeaddrinfo(addrs);
	free(req->reserved[0]);
	free(req);
}

/*
*==连接探测目标服务器==
*针对非INNO请求，响应防火墙探测行为，直接连接SNI对应的服务器
*1. 检查域名在地址解析缓存中是否已有相应的解析，有否进行TCP连接
*2. 需要进行域名解析，待回调后进行连接。
*/
void do_probe_connect(conn_context_t* tunnel, socket_ctx_t* ctx) {
	//如果不是inno session id,  将client 直接到到目标服务器
	const char * domainname = mbedtls_ssl_get_client_sni(&tunnel->ssl_ctx);
	tunnel->target_addr.addr4.sin_port = 443;
	if ( !domainname || strlen(domainname) < 1) {
		return;
	}
	//如果域名在已在缓存中存在
	union sockaddr_universal * query_addr = ip_addr_cache_retrieve_address(resolved_ip_cache, domainname, &malloc);
	if (query_addr) {
		struct sockaddr_in dest;
		dest.sin_family = AF_INET;
		dest.sin_port = htons(tunnel->target_addr.addr4.sin_port);
		dest.sin_addr = query_addr->addr4.sin_addr;
		tunnel->output_handle = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
		uv_tcp_init(uv_default_loop(), tunnel->output_handle);
		tunnel->output_handle->data = (void*)tunnel;
		uv_connect_t *conn_req = (uv_connect_t *)malloc(sizeof(uv_connect_t));
		conn_req->data = tunnel;
		uv_tcp_connect(conn_req, tunnel->output_handle, (const struct sockaddr *)&dest, on_outbround_listen_cb);
		trace("do_tls_target_request pull cache domain:%s ip:%s:%d", domainname, inet_ntoa(dest.sin_addr), tunnel->target_addr.addr4.sin_port);
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
	trace("uv_getaddrinfo_t domain:%s", query_req->reserved[0]);
	int ret = uv_getaddrinfo(uv_default_loop(), query_req, get_probe_addrinfo_done_cb, domainname, NULL, &hints);
	if (ret != 0) {
		free(query_req);
		query_req = NULL;
	}
}

/*
*==原始数据转发==
*针对非INNO请求，响应防火墙探测行为，直接转发SNI所对应的服务器数据
*/
void do_probe_forword(conn_context_t* tunnel, socket_ctx_t* socket) {
	char * data = socket->buf.base;
	size_t  size = (size_t)socket->buf_len;
#ifdef WIN32                                                                                                                          
	if (tunnel->input_handle && tunnel->output_handle &&  socket->handle->socket == tunnel->input_handle->socket) {
#else
	if (tunnel->input_handle && tunnel->output_handle &&  socket->handle == tunnel->input_handle) {
#endif
		char* write_data = (char*)malloc(size);
		memcpy(write_data, data, size);
		uv_buf_t write_buf = uv_buf_init(write_data, (unsigned int)size);
		uv_write_t *write_req = (uv_write_t *)malloc(sizeof(uv_write_t));
		write_req->data = write_data;
		hex_trace("do_data_forword uv_write to target", data, size);
		int ret = uv_write(write_req, (uv_stream_t*)tunnel->output_handle, &write_buf, 1, uv_socket_write_done_cb);
		return;
	}

#ifdef WIN32
	if (tunnel->output_handle && socket->handle->socket == tunnel->output_handle->socket) {
#else
	if (tunnel->output_handle && socket->handle->u.fd == tunnel->output_handle->u.fd) {
#endif 
		char* write_data = (char*)malloc(size);
		memcpy(write_data, data, size);
		uv_buf_t write_buf = uv_buf_init(write_data, (unsigned int)size);
		uv_write_t *write_req = (uv_write_t *)malloc(sizeof(uv_write_t));
		write_req->data = write_data;
		hex_trace("tls do_data_forword uv_write to client", data, size);
		int ret = uv_write(write_req, (uv_stream_t*)tunnel->input_handle, &write_buf, 1, uv_socket_write_done_cb);
		return;
	}
	trace("do_data_forword handless size:%d", size);
}

/*
*==域名解析回调==
*解析完成后将进入连接目标服务器状态
*/
static void getaddrinfo_done_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs) {
	if (status != 0 || addrs == NULL || !req || !req->data) {
		return;
	}
	//域名解析地址 + from socks5 addr:port
	char * domain = (char*)req->reserved[0];
	conn_context_t *tunnel = (conn_context_t *)req->data;
	struct sockaddr_in dest = *(const struct sockaddr_in*)addrs->ai_addr;
	dest.sin_port = htons(/*tunnel->target_addr.addr4.sin_port*/ 443 );
	if (ip_addr_cache_is_address_exist(resolved_ip_cache, domain) == false) {
		trace("getaddrinfo_done_cb push cache domain:%s ip:%s:%d", domain, inet_ntoa(dest.sin_addr), tunnel->target_addr.addr4.sin_port);
		union sockaddr_universal * address = (union sockaddr_universal*) malloc(sizeof(union sockaddr_universal));
		address->addr4.sin_addr = dest.sin_addr;
		address->addr4.sin_port = dest.sin_port;
		ip_addr_cache_add_address(resolved_ip_cache, domain, address);
	}
	//连接到目标服务器
	tunnel->output_handle = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
	uv_tcp_init(uv_default_loop(), tunnel->output_handle);
	tunnel->output_handle->data = (void*)tunnel;
	uv_connect_t *conn_req = (uv_connect_t *)malloc(sizeof(uv_connect_t));
	conn_req->data = (void*)tunnel;
	uv_tcp_connect(conn_req, tunnel->output_handle, (const struct sockaddr *)&dest, on_outbround_listen_cb);
	uv_freeaddrinfo(addrs);
	free(req->reserved[0]);
	free(req);
}

/*
* inbround 读数据回调函数
*/
void on_inbround_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
	conn_context_t *conn_ctx = (conn_context_t *)stream->data;
	if (nread > 0) {
		hex_trace("on_inbround_read_cb", buf->base, nread);
		//被识别为TLS后，ApplicationData 将不进行封装，直接转发
		if (conn_ctx->is_handle_tlsintls) {
			socket_ctx_t  ctx;
			ctx.buf = uv_buf_init(buf->base, nread);
			ctx.buf_len = nread;
			ctx.handle = conn_ctx->input_handle;
			trace("transfor tls data  read:%d", nread);
			tunnel_dispatcher(conn_ctx, &ctx);
			return;
		}

		// 1. 缓存原始网络数据 (交给 mbedTLS 处理)
		size_t new_buffer_len = conn_ctx->input_read_buffer_len + nread;
		char *new_buffer = (char *)realloc(conn_ctx->input_read_buffer, new_buffer_len);
		if (new_buffer == NULL) {
			fprintf(stderr, "memery alloc failed!\n");
			goto cleanup;
		}
		conn_ctx->input_read_buffer = new_buffer;
		memcpy(conn_ctx->input_read_buffer + conn_ctx->input_read_buffer_len, buf->base, nread);
		conn_ctx->input_read_buffer_len = new_buffer_len;
		free(buf->base);

		//握手过程
		if (conn_ctx->stage == tunnel_stage_tls_clientHello) {
			//char app_data[60480] = { 0 };
			//int  ret = mbedtls_ssl_read(&conn_ctx->ssl_ctx, (unsigned char*)app_data, sizeof(app_data));
			//if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
			//	goto cleanup;
			//}
			tunnel_dispatcher(conn_ctx, NULL);
		}
		//传输过程
		else if (conn_ctx->stage == tunnel_stage_tls_streaming) {
#ifdef FAKE_APPLICATION
			socket_ctx_t  ctx;
			ctx.buf = uv_buf_init(conn_ctx->input_read_buffer + 5, conn_ctx->input_read_buffer_len - 5);
			ctx.buf_len = conn_ctx->input_read_buffer_len - 5;
			ctx.handle = conn_ctx->input_handle;
			conn_ctx->input_read_buffer_len = 0;
			tunnel_dispatcher(conn_ctx, &ctx);
#else
			socket_ctx_t  ctx;
			ctx.buf = uv_buf_init(conn_ctx->input_read_buffer, conn_ctx->input_read_buffer_len);
			ctx.buf_len = conn_ctx->input_read_buffer_len;
			ctx.handle = conn_ctx->input_handle;
			conn_ctx->input_read_buffer_len = 0;
			tunnel_dispatcher(conn_ctx, &ctx);
#endif
		}
		//握手完成,  接收客户端目标地址访问请求
		else if (conn_ctx->stage == tunnel_stage_tls_stealhandle) {
			conn_ctx->stage = tunnel_stage_tls_handshaked;
#ifdef FAKE_APPLICATION
			socket_ctx_t  ctx;
			ctx.buf = uv_buf_init(conn_ctx->input_read_buffer + 5, conn_ctx->input_read_buffer_len - 5);
			ctx.buf_len = conn_ctx->input_read_buffer_len - 5;
			ctx.handle = conn_ctx->input_handle;
			conn_ctx->input_read_buffer_len = 0;
			tunnel_dispatcher(conn_ctx, &ctx);
#else
			socket_ctx_t  ctx;
			ctx.buf = uv_buf_init(conn_ctx->input_read_buffer, conn_ctx->input_read_buffer_len );
			ctx.buf_len = conn_ctx->input_read_buffer_len;
			ctx.handle = conn_ctx->input_handle;
			conn_ctx->input_read_buffer_len = 0;
			tunnel_dispatcher(conn_ctx, &ctx);
#endif

		}
		return;
	}
cleanup:
	if (stream) {
		uv_close((uv_handle_t*)stream, on_tls_close_cb);
	}else {
		if (buf->base) free(buf->base);
	}
}

// 新连接回调函数
void on_inbround_listen_cb(uv_stream_t *server, int status) {
	if (status < 0) {
		fprintf(stderr, "on_tls_listen_cb connection error: %s\n", uv_strerror(status));
		return;
	}
	trace("on_tls_listen_cb create new connect stattus:%d", status);
	// 1. 创建并初始化客户端上下文
	conn_context_t *conn_ctx = (conn_context_t*)malloc(sizeof(conn_context_t));
	memset(conn_ctx, 0, sizeof(conn_context_t));
	conn_ctx->input_handle = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
	uv_tcp_init(server->loop, conn_ctx->input_handle);
	conn_ctx->input_handle->data = (void*)conn_ctx;
	conn_ctx->stage = tunnel_stage_tls_clientHello;
	conn_ctx->is_clientHello = true; //第一个收到的数据将是ClientHello;
	conn_channel_count++;
	// 2. 接受连接
	if (uv_accept(server, (uv_stream_t *)conn_ctx->input_handle) != 0) {
		trace("on_tls_listen_cb uv_accept error");
		uv_close((uv_handle_t*)conn_ctx->input_handle, on_tls_close_cb);
		return;
	}
	// 3. 初始化 mbedTLS 上下文
	mbedtls_ssl_init(&conn_ctx->ssl_ctx);
	if (mbedtls_ssl_setup(&conn_ctx->ssl_ctx, &conf) != 0) {
		trace("on_tls_listen_cb mbedtls_ssl_setup failed");
		uv_close((uv_handle_t*)conn_ctx->input_handle, on_tls_close_cb);
		return;
	}
	conn_ctx->ssl_ctx.private_user_data.n = sizeof(void*);
	conn_ctx->ssl_ctx.private_user_data.p = (void*)conn_ctx;
	// 设置 mbedTLS 的 I/O 委托给我们自定义的函数，并传入上下文
	mbedtls_ssl_set_bio(&conn_ctx->ssl_ctx, conn_ctx, my_mbedtls_send, my_mbedtls_recv, my_mbedtls_recv_timeout);
	// 启动读操作，等待客户端数据
	uv_read_start((uv_stream_t*)conn_ctx->input_handle, alloc_buffer_cb, on_inbround_read_cb);
	// 启动 TLS 握手 (非阻塞模式，它会返回 WANT_READ/WANT_WRITE)
	//mbedtls_ssl_handshake(&conn_ctx->ssl_ctx);
	trace("on_tls_listen_cb Accepted new connection. conn_channel_count:%d", conn_channel_count);
}

/*
*==握手阶段处理==
*1. 判段sessionID是否为INNO自定义ID, 否则直接跟据clientHello的SNI进行透明转发
*2. 如果SSL握手完成，检查sessionID是否为token;
*/
void do_inbround_handshake(conn_context_t* tunnel, socket_ctx_t* ctx) {
	// 探测处理流程,检测是否非inno session, 否则直接转到至目标服务器
#ifdef PROBE_HANDLE
	if (  tunnel->is_clientHello &&  0==mbedtls_ssl_handshake_clienthello(&tunnel->ssl_ctx)) {
		trace("do_inbround_handshake  MBEDTLS_SSL_CLIENT_HELLO");
		unsigned char session_id_out[32] = { 0 };
		mbedtls_ssl_get_client_sessionid(&tunnel->ssl_ctx, session_id_out);
		tunnel->is_clientHello = false;
		if( !check_session_id(session_id_out )){
			do_probe_connect(tunnel, ctx);
			return;
		}
	}
#endif

	char app_data[60480] = { 0 };
	int  ret = mbedtls_ssl_read(&tunnel->ssl_ctx, (unsigned char*)app_data, sizeof(app_data));
	if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
			uv_close((uv_handle_t*)tunnel->input_handle, on_tls_close_cb);
			return;
	}

	//认证处理...( 2026)
	if ( !tunnel->is_verified ) {
		struct session_id sid = { 0 };
		unsigned char sid_buf[32] = { 0 };
		char token_for_key[40] = { 0 };
		mbedtls_ssl_get_client_sessionid(&tunnel->ssl_ctx, sid_buf);
		memcpy(&sid, sid_buf, 32);
		uuid_to_string(sid.token, token_for_key);
		trace("do_inbround_handshake  user token:%s", token_for_key);
		//只有当pkg_type==1时，才需要进行验证。
		if (sid.pkg_type == 0x01) {
			trace("usermgr_is_online ");
			if (usermgr_is_online(my_usermgr, token_for_key)) {
				tunnel->is_verified = true;
			}else {
				trace("shutdown");
				tunnel->stage = tunnel_stage_shutdown;
				tunnel_dispatcher(tunnel, ctx);
			}
		}
	}



	//if (tunnel->is_clientHello && 0 == mbedtls_ssl_handshake_clienthello(&tunnel->ssl_ctx)) {
	//	trace("do_inbround_handshake  MBEDTLS_SSL_CLIENT_HELLO");
	//	return;
	//}

	////握手过程检测,从sessionID中获取token进行检测
	//if (tunnel->ssl_ctx.private_state != MBEDTLS_SSL_HANDSHAKE_OVER) {
	//	int ret = mbedtls_ssl_handshake(&tunnel->ssl_ctx);
	//	trace("do_inbround_handshake sni:%s", tunnel->probe_sni);
	//	//if (ret == 0) {
	//	//	tunnel->stage = tunnel_stage_tls_handshaked;
	//	//	trace("do_inbround_handshake successful.");
	//	//	if (!tunnel->is_verified) {
	//	//		struct session_id sid = { 0 };
	//	//		unsigned char sid_buf[32] = { 0 };
	//	//		char token_for_key[40] = { 0 };
	//	//		mbedtls_ssl_get_peer_sessionid(&tunnel->ssl_ctx, sid_buf);
	//	//		memcpy(&sid, sid_buf, 32);
	//	//		uuid_to_string(sid.token, token_for_key);
	//	//		trace("do_inbround_handshake  user token:%s", token_for_key);
	//	//		//只有当pkg_type==1时，才需要进行验证。
	//	//		if (sid.pkg_type == 0x01) {
	//	//			trace("usermgr_is_online ");
	//	//			if (usermgr_is_online(my_usermgr, token_for_key)) {
	//	//				tunnel->is_verified = true;
	//	//			}else {
	//	//				trace("shutdown");
	//	//				tunnel->stage = tunnel_stage_shutdown;
	//	//				tunnel_dispatcher(tunnel, ctx);
	//	//			}
	//	//		}
	//	//	}
	//	//	return;
	//	//}
	//	//char error_buf[100];
	//	//mbedtls_strerror(ret, error_buf, sizeof(error_buf));
	//	//trace("mbedtls_ssl_handshake returned -0x%x: %s\n", (unsigned int)-ret, error_buf);
	//}



}

/*
*==释放连接资源==
*/
void on_outbround_close_cb(uv_handle_t *handle) {
	trace("on_target_close_cb");
	conn_context_t *conn_ctx = (conn_context_t *)handle->data;
	if (conn_ctx->output_read_buffer) {
		free(conn_ctx->output_read_buffer);
		conn_ctx->output_read_buffer = NULL;
	}
	free(conn_ctx->output_handle);
	conn_ctx->output_handle = NULL;
	conn_ctx->stage = tunnel_stage_shutdown;
	tunnel_dispatcher(conn_ctx, NULL);
}

// 目标服务器返回信息
void on_outbround_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
	conn_context_t *conn_ctx = (conn_context_t *)stream->data;
	if ( nread > 0 ) {
		socket_ctx_t  ctx;
		ctx.buf = *buf;
		ctx.buf_len = nread;
		ctx.handle = conn_ctx->output_handle;
		hex_trace("on_target_read_cb form target", buf->base, nread);
		tunnel_dispatcher(conn_ctx, &ctx);
#ifdef TLSINTLS_HANDLE
		if (!conn_ctx->is_handle_tlsintls) {
			//识别为目标服务器的Server HelloDone 后将直接转发接下去的数据 
			//16 03 03 00 04 0e 00 00 00
			char * data = &buf->base[nread - 9];
			if (data[0] == 0x16 && data[5] == 0x0E) {
				trace("server hello done, Identify as TLS packets and forward directly.");
				conn_ctx->is_handle_tlsintls = true;
			}
		}
#endif
	}else {
		trace("on_target_read_cb [%d] to close", nread);
		uv_close((uv_handle_t*)stream, on_outbround_close_cb);
	}
}

// 连接到目标服务器
void on_outbround_listen_cb(uv_connect_t *req, int status) {
	conn_context_t * tunnel = (conn_context_t *)req->data;
	if (status < 0) {
		trace("on_outbround_listen_cb  conn fail: %s", uv_strerror(status));
		tunnel->stage = tunnel_stage_shutdown;
		socket_ctx_t  ctx;
		ctx.handle = tunnel->output_handle;
		tunnel_dispatcher(tunnel, &ctx);
		return;
	}
	trace("on_outbround_listen_cb create new connect.");
	uv_read_start((uv_stream_t *)tunnel->output_handle, alloc_buffer_cb, on_outbround_read_cb);
	static char * sz_rsp = "connect target is ok.";
	size_t size = (size_t)strlen(sz_rsp);
	fake_mbedtls_send( tunnel, (const unsigned char *)sz_rsp, size);
	tunnel->stage = tunnel_stage_tls_streaming;
}

/*
==连接目标服务器(这里将收到第一个包)==
* 包括S5的目标地址请求
* 用户认证相关信息
*/
void do_inbround_target_request(conn_context_t* tunnel, socket_ctx_t* socket) {
	//目标服务器解析或连接
	size_t offset = 0;
	struct socks5_address s5addr;
	if (!socks5_address_parse((const uint8_t*)socket->buf.base, socket->buf.len, &s5addr, &offset)) {
		tunnel->stage = tunnel_stage_shutdown;
		tunnel_dispatcher(tunnel, socket);
		return;
	}
	tunnel->target_addr.addr4.sin_port = s5addr.port;

	//带有认证信息的target request
	if (socket->buf.len - offset == sizeof(auth_info_t)) {
		struct auth_info authinfo;
		memcpy(&authinfo, socket->buf.base + offset, sizeof(auth_info_t));
		//打印认证信息
		char str_user_name[40] = { 0 };
		char str_user_cipher[40] = { 0 };
		uuid_to_string(authinfo.user_name, str_user_name);
		uuid_to_string(authinfo.user_cipher, str_user_cipher);
		trace("do_inbround_target_request name:%s  cipher:%s", str_user_name, str_user_cipher);
		//认证逻辑处理,成功加入用户连接缓存列表
		char acc_key[256] = { 0 };
		sprintf(acc_key, "%d_%"PRIu64":%s@%s", authinfo.app_type, authinfo.user_id, str_user_name, str_user_cipher);
		if (usermgr_local_auth(my_usermgr, acc_key)) {
			const uint8_t authinfo_md5[16] = {0};
			mbedtls_md5((uint8_t *)&authinfo, sizeof(struct auth_info), (uint8_t *)authinfo_md5);
			const char key[40] = { 0 };
			uuid_to_string(authinfo_md5, (char*)key);
			if( usermgr_add_user(my_usermgr, key, &authinfo)){
				usermgr_online_save(my_usermgr);
			}
			trace("do_inbround_target_request add new clinet key:%s", acc_key);
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
			tunnel->output_handle = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
			uv_tcp_init(uv_default_loop(), tunnel->output_handle);
			tunnel->output_handle->data = (void*)tunnel;
			uv_connect_t *conn_req = (uv_connect_t *)malloc(sizeof(uv_connect_t));
			conn_req->data = tunnel;
			uv_tcp_connect(conn_req, tunnel->output_handle, (const struct sockaddr *)&dest, on_outbround_listen_cb);
			trace("do_inbround_target_request pull cache domain:%s ip:%s:%d", s5addr.addr.domainname, inet_ntoa(dest.sin_addr), s5addr.port);
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
		trace("uv_getaddrinfo_t domain:%s", query_req->reserved[0]);
		int ret = uv_getaddrinfo(uv_default_loop(), query_req, getaddrinfo_done_cb, s5addr.addr.domainname, NULL, &hints);
		if (ret != 0) {
			free(query_req);
			query_req = NULL;
		}
	}

	//S5提交的是IP的处理
	else if (s5addr.addr_type == SOCKS5_ADDRTYPE_IPV4) {
		struct sockaddr_in dest;
		dest.sin_family = AF_INET;
		dest.sin_port = htons(s5addr.port);
		dest.sin_addr = s5addr.addr.ipv4;
		tunnel->output_handle = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
		uv_tcp_init(uv_default_loop(), tunnel->output_handle);
		tunnel->output_handle->data = (void*)tunnel;
		uv_connect_t *conn_req = (uv_connect_t *)malloc(sizeof(uv_connect_t));
		conn_req->data = tunnel;
		uv_tcp_connect(conn_req, tunnel->output_handle, (const struct sockaddr *)&dest, on_outbround_listen_cb);
		trace("do_inbround_target_request connect target server ip:%s port:%d", inet_ntoa(dest.sin_addr), s5addr.port);
	}
	return;
}

/*
*==关闭通道==
*只有 input 和 output 都断开后才释放通道
*/
void do_stage_shutdown(conn_context_t* tunnel, socket_ctx_t* ctx) {
	if (tunnel->input_handle) {
		trace("do_stage_shutdown to close input handle");
		if (!uv_is_closing((uv_handle_t*)tunnel->input_handle)) {
			uv_close((uv_handle_t*)tunnel->input_handle, on_tls_close_cb);
		}
	}
	else if (tunnel->output_handle) {
		trace("do_stage_shutdown to close output handle");
		if (!uv_is_closing((uv_handle_t*)tunnel->output_handle)) {
			uv_close((uv_handle_t*)tunnel->output_handle, on_outbround_close_cb);
		}
	}
	else if (tunnel->steal_handle) {
		trace("do_stage_shutdown to close steal handle");
		if (!uv_is_closing((uv_handle_t*)tunnel->steal_handle)) {
			uv_close((uv_handle_t*)tunnel->steal_handle, on_steal_close_cb);
		}
	}
	if (tunnel->input_handle == tunnel->output_handle &&  tunnel->steal_handle == NULL) {
		conn_channel_count--;
		mbedtls_ssl_free(&tunnel->ssl_ctx);
		trace("do_stage_shutdown conn_channel_count:%d", conn_channel_count);
		free(tunnel);
	}
	(void)ctx;
}

////////////////////////////////////////////////////////////////////////////fallback////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void do_probe_catch(conn_context_t* tunnel, socket_ctx_t* socket) {
	char * data = socket->buf.base;
	size_t  size = (size_t)socket->buf_len;
	//
	//#ifdef WIN32                                                                                                                          
	//	if (tunnel->input_handle && tunnel->output_handle &&  socket->handle->socket == tunnel->input_handle->socket) {
	//#else
	//	if (tunnel->input_handle && tunnel->output_handle &&  socket->handle == tunnel->input_handle) {
	//#endif
	//		char* write_data = (char*)malloc(size);
	//		memcpy(write_data, data, size);
	//		uv_buf_t write_buf = uv_buf_init(write_data, (unsigned int)size);
	//		uv_write_t *write_req = (uv_write_t *)malloc(sizeof(uv_write_t));
	//		write_req->data = write_data;
	//		hex_trace("do_data_forword uv_write to target", data, size);
	//		int ret = uv_write(write_req, (uv_stream_t*)tunnel->output_handle, &write_buf, 1, uv_socket_write_done_cb);
	//		return;
	//	}
	//	}
}
//////////////////////////////////////////////////////////////////////////////steal////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void on_steal_close_cb(uv_handle_t *handle) {
	trace("on_steal_close_cb handle flags:%d", handle->flags);
	conn_context_t *conn_ctx = (conn_context_t *)handle->data;
	if (conn_ctx->steal_handle) {
		add_shcrt(my_shcrtmgr, conn_ctx->probe_sni, conn_ctx->server_hello, conn_ctx->server_hello_len);
		free(conn_ctx->steal_handle);
		conn_ctx->steal_handle = NULL;
	}
	conn_ctx->stage = tunnel_stage_shutdown;
	tunnel_dispatcher(conn_ctx, NULL);
}

// 伪造样本获取流程
static void on_steal_addrinfo_done_cb(uv_getaddrinfo_t *req, int status, struct addrinfo *addrs) {
	if (status != 0 || addrs == NULL || !req || !req->data) {
		return;
	}
	//域名解析地址 + from socks5 addr:port
	char * domain = (char*)req->reserved[0];
	conn_context_t *tunnel = (conn_context_t *)req->data;
	struct sockaddr_in dest = *(const struct sockaddr_in*)addrs->ai_addr;
	dest.sin_port = htons(/*tunnel->target_addr.addr4.sin_port*/ 443);
	tunnel->steal_handle = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
	uv_tcp_init(uv_default_loop(), tunnel->steal_handle);
	tunnel->steal_handle->data = (void*)tunnel;
	uv_connect_t *conn_req = (uv_connect_t *)malloc(sizeof(uv_connect_t));
	conn_req->data = (void*)tunnel;
	uv_tcp_connect(conn_req, tunnel->steal_handle, (const struct sockaddr *)&dest, on_steal_listen_cb);
	uv_freeaddrinfo(addrs);
	free(req->reserved[0]);
	free(req);
}

//收到客户端CH获取SNI后，缓存获取或偷取SH
int on_steal_sni_callback(void *p_info, mbedtls_ssl_context *ssl, const unsigned char *name, size_t name_len) {
	trace("on_steal_sni_callback sni:%s", name);
	conn_context_t *conn_ctx = (conn_context_t *)ssl->private_user_data.p;
	strncpy(conn_ctx->probe_sni, name, name_len);

	//如果在缓存中找到相应的server_hello 
	char * hello_data = NULL;
	size_t hello_len = 0;
	if( get_shcrt_data(my_shcrtmgr, name, &hello_data, &hello_len) == 0 && hello_len > 0 ){
		char* write_data = (char*)malloc(hello_len);
		memcpy(write_data, hello_data, hello_len);
		uv_buf_t write_buf = uv_buf_init(write_data, (unsigned int)hello_len);
		uv_write_t *write_req = (uv_write_t *)malloc(sizeof(uv_write_t));
		write_req->data = write_data;
		hex_trace("on_steal_sni_callback source to client", write_data, hello_len);
		//替换 sessionID
		unsigned char sid_buf[32] = { 0 };
		mbedtls_ssl_get_client_sessionid(&conn_ctx->ssl_ctx, sid_buf);
		memcpy(write_data+44, sid_buf, 32);
		int ret = uv_write(write_req, (uv_stream_t*)conn_ctx->input_handle, &write_buf, 1, uv_socket_write_done_cb);
		conn_ctx->stage = tunnel_stage_tls_stealhandle;
		return;
	}
	//如果域名没有获取真实server_hello，将进入以下流程
	conn_ctx->stage = tunnel_stage_tls_stealhandle;
	tunnel_dispatcher(conn_ctx, NULL);
	return 0;
}

void on_steal_listen_cb(uv_connect_t *req, int status) {
	conn_context_t * tunnel = (conn_context_t *)req->data;
	if (status < 0) {
		ftrace("on_sample_listen_cb  conn fail: %s", uv_strerror(status));
		tunnel->stage = tunnel_stage_shutdown;
		socket_ctx_t  ctx;
		ctx.handle = tunnel->output_handle;
		tunnel_dispatcher(tunnel, &ctx);
		return;
	}
	if ( tunnel->steal_handle ) {
		uv_read_start((uv_stream_t *)tunnel->steal_handle, alloc_buffer_cb, on_steal_read_cb);
		size_t size = tunnel->ssl_ctx.private_in_msglen + 5;
		char* write_data = (char*)malloc(size);
		memcpy(write_data, tunnel->ssl_ctx.private_in_hdr, size);
		uv_buf_t write_buf = uv_buf_init(write_data, (unsigned int)size);
		uv_write_t *write_req = (uv_write_t *)malloc(sizeof(uv_write_t));
		write_req->data = write_data;
		hex_trace("on_steal_listen_cb write client_hello to sni", tunnel->ssl_ctx.private_in_hdr, size);
		int ret = uv_write(write_req, (uv_stream_t*)tunnel->steal_handle, &write_buf, 1, uv_socket_write_done_cb);
	}
}

//收到偷取的ClientHello&Cert, 缓存并发送给客户端
void on_steal_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
	conn_context_t *conn_ctx = (conn_context_t *)stream->data;
	if (nread > 0) {
		char* write_data = (char*)malloc(nread);
		memcpy(write_data, buf->base, nread);
		uv_buf_t write_buf = uv_buf_init(write_data, (unsigned int)nread);
		uv_write_t *write_req = (uv_write_t *)malloc(sizeof(uv_write_t));
		write_req->data = write_data;
		hex_trace("on_steal_read_cb source to client", write_data, nread);
		int ret = uv_write(write_req, (uv_stream_t*)conn_ctx->input_handle, &write_buf, 1, uv_socket_write_done_cb);
		//如果 HandShake 过程完成，断开steal目标的连接
		memcpy(conn_ctx->server_hello + conn_ctx->server_hello_len, buf->base,  nread);
		conn_ctx->server_hello_len += nread;
		return;
	}
	ftrace("on_steal_read_cb [%d] to close", nread);
	uv_close((uv_handle_t*)stream, NULL);
}

//偷证书处理流程开始
void do_stealhandle( conn_context_t* tunnel, socket_ctx_t* socket ) {
	memcpy(tunnel->session_id, tunnel->ssl_ctx.private_in_hdr + 44, 32);
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
		free(query_req);
		query_req = NULL;
	}
}

/////////////////////////////////////////////////////////////////////Dispath////////////////////////////////////////////////////////////////////////////////////////////////////

//dispath (隧道状态机调度函数)
static void tunnel_dispatcher(conn_context_t* tunnel, socket_ctx_t* socket) {
	trace("tunnel_dispatcher enter case:%s", tunnel_stage_string(tunnel->stage));
	switch (tunnel->stage) {
	case tunnel_stage_tls_clientHello:
		do_inbround_handshake(tunnel, socket);
		break;

	case tunnel_stage_tls_stealhandle: 
		do_stealhandle(tunnel, socket);
		break;

	case tunnel_stage_tls_handshaked: // 1: 接收到目标地址包和身份验证信息
		do_inbround_target_request(tunnel, socket);
		break;

	//case tunnel_stage_tls_probe_streaming: //获取probe 服务器ServerHello阶段
	//	do_probe_catch(tunnel, socket);
	//	break;

	case tunnel_stage_tls_streaming: // 2: DNS 解析    
		do_data_forword(tunnel, socket);
		break;

	case tunnel_stage_probe_streaming://3: 连接目标服务器
		do_probe_forword(tunnel, socket);
		break;

	case tunnel_stage_shutdown:// 5: 关闭连接/资源清理
		do_stage_shutdown(tunnel, socket);
		break;
	}
}

// 开始监听及 LOOP 开启线程函数
void * uv_loop_thread_function(void* arg) {
	unsigned short  port = *(unsigned short*)arg;
	uv_loop_t *loop = uv_default_loop();
	uv_tcp_t server_socket;
	struct sockaddr_in addr;
	uv_tcp_init(loop, &server_socket);
	uv_ip4_addr("0.0.0.0", port, &addr);
	uv_tcp_bind(&server_socket, (const struct sockaddr*)&addr, 0);
	int lsn = uv_listen((uv_stream_t*)&server_socket, 1024, on_inbround_listen_cb);
	trace("start server listening on:%d error:%s\n", port, uv_strerror(lsn));
	uv_run(loop, UV_RUN_DEFAULT);
	return NULL;
}

//初始化mbedtls库相关参数配置
int init_tls_server_config(void) {
	int ret = 0;
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_ssl_config_init(&conf);
	mbedtls_x509_crt_init(&cacert);
	mbedtls_pk_init(&pkey);

	// 1. 播种随机数发生器
	ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
	if (ret != 0) { fprintf(stderr, "ctr_drbg_seed failed: %d\n", ret); return ret; }

	// 2. 加载服务器证书和私钥 (使用 mbedTLS 内置测试证书)
	//ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *)s_mbedtls_test_srv_crt_rsa, strlen(s_mbedtls_test_srv_crt_rsa)+1);
	//if (ret != 0) { fprintf(stderr, "crt_parse failed: %d\n", ret); return ret; }
	//ret = mbedtls_pk_parse_key(&pkey, (const unsigned char *)s_mbedtls_test_srv_key_rsa, strlen(s_mbedtls_test_srv_key_rsa)+1, (const unsigned char *)s_mbedtls_test_srv_pwd_rsa, strlen(s_mbedtls_test_srv_pwd_rsa), NULL, 0);
	//if (ret != 0) { fprintf(stderr, "pk_parse_key failed: %d\n", ret); return ret; }

	// 3. 配置 SSL
	ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) { fprintf(stderr, "ssl_config_defaults failed: %d\n", ret); return ret; }

	mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4); // TLS 1.3
	mbedtls_ssl_conf_max_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4); // TLS 1.3

	// 4. 设置配置
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);         // 设置随机数生成器
	mbedtls_ssl_conf_sni(&conf, on_steal_sni_callback, NULL);                          // 设置 SNI 回调
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);           // 设置认证模式：不要求客户端证书

	// 5. 绑定证书和私钥
	//ret = mbedtls_ssl_conf_own_cert(&conf, &cacert, &pkey);
	//if (ret != 0) { fprintf(stderr, "ssl_conf_own_cert failed: %d\n", ret); return ret; }
	return 0;
}

void free_tls_server_config(void) {
	mbedtls_pk_free(&pkey);
	mbedtls_x509_crt_free(&cacert);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
}

//将ssl缓存数据全部发送完成
int mbedtls_ssl_write_all(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t len) {
	int ret = 0;
	size_t sent = 0;
	do {
		ret = mbedtls_ssl_write(ssl, buf + sent, len - sent);
		if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
			continue;
		}if (ret < 0) {
			trace("do_data_forword ret:%d", ret);
			break;
		}
		sent += ret;
	} while (sent < len);
	return ret;
}

//tls 数据传输
void do_data_forword(conn_context_t* tunnel, socket_ctx_t* socket) {
	char * data = socket->buf.base;
	size_t  size = (size_t)socket->buf_len;

#ifdef WIN32                                                                                                                          
	if (tunnel->input_handle && tunnel->output_handle &&  socket->handle->socket == tunnel->input_handle->socket) {
#else
	if (tunnel->input_handle && tunnel->output_handle &&  socket->handle == tunnel->input_handle) {
#endif
		char* write_data = (char*)malloc(size);
		memcpy(write_data, data, size);
		uv_buf_t write_buf = uv_buf_init(write_data, (unsigned int)size);
		uv_write_t *write_req = (uv_write_t *)malloc(sizeof(uv_write_t));
		write_req->data = write_data;
		hex_trace("do_data_forword uv_write to target", data, size);
		int ret = uv_write(write_req, (uv_stream_t*)tunnel->output_handle, &write_buf, 1, uv_socket_write_done_cb);
		return;
	}

#ifdef WIN32
	if (tunnel->output_handle && socket->handle->socket == tunnel->output_handle->socket) {
#else
	if (tunnel->output_handle && socket->handle->u.fd == tunnel->output_handle->u.fd) {
#endif 
		if (tunnel->is_handle_tlsintls) {
			char* write_data = (char*)malloc(size);
			memcpy(write_data, data, size);
			uv_buf_t write_buf = uv_buf_init(write_data, (unsigned int)size);
			uv_write_t *write_req = (uv_write_t *)malloc(sizeof(uv_write_t));
			write_req->data = write_data;
			hex_trace("tls do_data_forword uv_write to client", data, size);
			int ret = uv_write(write_req, (uv_stream_t*)tunnel->input_handle, &write_buf, 1, uv_socket_write_done_cb);
		}
		else {
			hex_trace("do_data_forword mbedtls_ssl_write_all to client", data, size);
			//int ret = mbedtls_ssl_write_all(&tunnel->ssl_ctx, (const unsigned char*)data, size);
			fake_mbedtls_send(tunnel, (const unsigned char*)data, size);
		}
		return;
	}
	trace("do_data_forword handless size:%d", size);
}

// main 主函数
int main(int argc, char * argv[]) {
	trace("reality - server");
	uv_loop_t *loop = uv_default_loop();
	my_config = configure_create(argc, argv);
	resolved_ip_cache = ip_addr_cache_create(IP_CACHE_EXPIRE_INTERVAL_MIN);
	my_usermgr = usermgr_create();
	//my_certmgr = certmgr_create();
	my_shcrtmgr = shcrtmgr_create();
	// 初始化 TLS 服务器全局配置 (证书、私钥、会话管理等)
	init_tls_server_config();

	// uv thread: 为每个配置的端口创建一个线程来运行 libuv 事件循环和监听
	pthread_t thread_uv[32];
	for (size_t t = 0; t < 32; t++) {	
		unsigned short  port = my_config->ports[t];
		if (port > 0 && port < 65535) {
			if (pthread_create(&thread_uv[t], NULL, uv_loop_thread_function, (void*)&my_config->ports[t]) != 0) {
				trace("pthread_create Fail.");
				return 1;
			}
		}
	}

	// main thread (主线程用于接收用户命令)
	while ( true ) {
		static char sz[256] = { 0 };
		if (fgets(sz, 256, stdin) == NULL)
			continue;
		else if (strcmp(sz, "exit\n") == 0) {
			break;
		}
		else if (strcmp(sz, "print online\n") == 0) {
			print_online_user(my_usermgr);
			continue;
		}
		else if (strcmp(sz, "print local\n") == 0) {
			print_local_user(my_usermgr);
			continue;
		}
		print_text_in_color(stderr, "cmd:", text_color_blue);
	}
	// 清理 mbedTLS 全局资源
	free_tls_server_config();
	// 释放配置、缓存和用户管理器资源
	ip_addr_cache_destroy(resolved_ip_cache);
	configure_destroy(my_config);
	usermgr_destroy(my_usermgr);
	//certmgr_destroy(my_certmgr);
	shcrtmgr_destroy(my_shcrtmgr);
	resolved_ip_cache = NULL;
	my_usermgr = NULL;
	uv_stop(loop);
	return 0;
}