// xClient.c : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <uv.h> // libuv 库，用于异步I/O
#include <mbedtls/ssl.h> // mbedTLS SSL/TLS 核心
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl_cache.h>
#include <mbedtls/md5.h> // 用于身份验证信息的MD5计算
#ifdef WIN32
#include <process.h >
#endif
#include <stdlib.h>
#include <pthread.h> // 线程操作
#include <time.h>
#include "../s5.h" // SOCKS5 协议处理
#include "../text_in_color.h" // 可能是用于彩色输出的辅助文件
#include "../sockaddr_universal.h" // 通用地址结构体
#include "../configure.h" // 配置信息
#include "../mycert.h" // 自定义证书文件

// http://ipv4.download.thinkbroadband.com/20MB.zip  // 示例下载链接，可能是测试用

// mbedTLS 全局配置和上下文
mbedtls_ssl_config conf;
mbedtls_x509_crt cacert;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
configure_t * my_config = NULL; // 程序配置

#define TLSINTLS_HANDLE      // 开启 TlsinTls 处理, 只有 TLS1.3 才能开启 (此处注释提及TLS1.3，但代码中强制限制为TLS1.2)

/* Session states. */
// 隧道连接的阶段映射宏
#define TUNNEL_STAGE_MAP(V)   \
    V( 0, tunnel_stage_s5_handshake, "tunnel_stage_s5_handshake")  \
    V( 1, tunnel_stage_s5_connrequest,  "tunnel_stage_s5_connrequest")  \
    V( 2, tunnel_stage_tls_handshak,  "tunnel_stage_tls_handshak")  \
	V( 3, tunnel_stage_tls_handshaked,  "tunnel_stage_tls_handshaked")  \
    V( 4, tunnel_stage_indicate_target,  "tunnel_stage_indicate_target")  \
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
	int result;
	uv_tcp_t * handle;
	uv_timer_t timer_handle;
	union uv_any_req req;
	struct uv_buf_t buf;
	size_t buf_len;
}socket_ctx_t;

// VPN 连接上下文 (核心结构体，保存隧道状态)
typedef struct conn_context {
	enum tunnel_stage stage; // 当前隧道阶段
	uv_tcp_t * input_handle; // 客户端连接 (SOCKS5)
	char *input_read_buffer;
	size_t input_read_buffer_len;
	size_t input_read_buffer_offset;
	uv_tcp_t * output_handle; // 远程服务器连接 (VPS/TLS)
	char *output_read_buffer; // 远程服务器接收数据的缓存 (用于 mbedTLS 接收回调)
	size_t output_read_buffer_len;
	size_t output_read_buffer_offset;
	mbedtls_ssl_context ssl_ctx; // mbedTLS SSL/TLS 上下文
	struct uv_buf_t target_address_pkg; // SOCKS5 目标地址请求包
	bool is_handle_tlsintls; // 是否启用 TLS-in-TLS 转发 (直接转发 TLS 记录)
} conn_context_t;

// 隧道状态机调度函数
static void tunnel_dispatcher(conn_context_t* tunnel, socket_ctx_t* socket);
// mbedTLS 发送回调
int my_mbedtls_send(void *ctx, const unsigned char *buf, size_t len);
// mbedTLS 接收回调
int my_mbedtls_recv(void *ctx, unsigned char *buf, size_t len);
// 连接远程服务器回调
void on_outbound_connect_cb(uv_connect_t *req, int status);

// 成员定义 (全局变量)
static unsigned int conn_context_count = 0; // 当前连接数
bool had_verified = false; // 是否已完成身份验证 (用于会话ID或首次发送数据)
auth_info_t  my_authinfo; // 身份验证信息
uint8_t  my_authinfo_md5[16] = { 0 }; // 身份验证信息的 MD5

// socket 写入完成回调
static void socket_write_done_cb(uv_write_t* req, int status) {
	//trace("socket_write_done_cb status:%d", status);
	char* write_buf = (char*)req->data;
	if (write_buf) {
		free(write_buf); // 释放写入缓冲区
		write_buf = NULL;
	}
	free(req); // 释放请求结构体
}

// 写入数据到指定 socket
void socket_ctx_write(struct socket_ctx* socket, const void* data, size_t len) {
	if (socket->handle) {
		uv_buf_t buf;
		uv_write_t* req;
		// 复制数据到新的缓冲区，确保异步写入时数据有效
		char * write_buf = (char*)calloc(len + 1, sizeof(*write_buf));
		memcpy(write_buf, data, len);
		buf = uv_buf_init(write_buf, (unsigned int)len);
		req = (uv_write_t*)calloc(1, sizeof(uv_write_t));
		req->data = write_buf; // 将缓冲区指针作为 req->data 传递，以便在回调中释放
		int ret = uv_write(req, (uv_stream_t*)socket->handle, &buf, 1, socket_write_done_cb);
		trace("socket_ctx_write len:%d  ret:%d", len, ret);
	}
}

// 缓冲区分配回调 (libuv 读操作前调用)
void alloc_buffer_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
	buf->base = (char *)malloc(suggested_size);
	buf->len = suggested_size;
}

////////////////////////////////////////////// s5 /////////////////////////////////////////////////////////////////////

// 释放 SOCKS5 (客户端) 连接资源回调
void on_inbound_close_cb(uv_handle_t *handle) {
	trace("on_inbound_close_cb handle flags:%d", handle->flags);
	conn_context_t *conn_ctx = (conn_context_t *)handle->data;
	// 释放客户端读取缓冲区
	if (conn_ctx->input_read_buffer) {
		free(conn_ctx->input_read_buffer);
		conn_ctx->input_read_buffer = NULL;
	}
	// 释放客户端 handle
	free(conn_ctx->input_handle);
	conn_ctx->input_handle = NULL;
	conn_ctx->stage = tunnel_stage_shutdown;
	// 切换到关闭阶段，触发资源清理
	tunnel_dispatcher(conn_ctx, handle->data);
}

// 读数据回调函数 (SOCKS5 客户端数据到达)
void on_inbound_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
	conn_context_t *conn_ctx = (conn_context_t *)stream->data;
	if (nread > 0) {
		hex_trace("on_inbound_read_cb", buf->base, nread);
		socket_ctx_t  ctx;
		ctx.buf = uv_buf_init(buf->base, nread);
		ctx.buf_len = nread;
		ctx.handle = conn_ctx->input_handle;
		// 数据交给隧道调度器处理
		tunnel_dispatcher(conn_ctx, &ctx);
		free(buf->base); // 释放 libuv 分配的缓冲区
	}
	else if (nread == UV_EOF || nread < 0) {
		// EOF 或错误，关闭连接
		trace("on_inbound_read_cb %s", uv_strerror((int)nread));
		uv_close((uv_handle_t*)stream, on_inbound_close_cb);
	}
}

// SOCKS5 监听回调 (新客户端连接到达)
void on_inbound_listen_cb(uv_stream_t *server, int status) {
	if (status < 0) {
		trace("on_inbound_listen_cb connection error: %s\n", uv_strerror(status));
		return;
	}
	uv_tcp_t * input_handle = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
	uv_tcp_init(server->loop, input_handle);
	// 2. 接受新连接
	if (uv_accept(server, (uv_stream_t *)input_handle) != 0) {
		trace("uv_accept error.");
		uv_close((uv_handle_t*)input_handle, NULL);
		return;
	}
	// 1. 创建并初始化连接上下文
	conn_context_t *conn_ctx = (conn_context_t*)malloc(sizeof(conn_context_t));
	memset(conn_ctx, 0, sizeof(conn_context_t));
	conn_ctx->input_handle = input_handle;
	conn_ctx->input_handle->data = (void*)conn_ctx; // 将上下文绑定到 handle
	conn_ctx->stage = tunnel_stage_s5_handshake; // 初始阶段：SOCKS5 握手
	conn_context_count++;
	// 3. 开始读取，等待 SOCKS5 Hello 数据
	uv_read_start((uv_stream_t *)conn_ctx->input_handle, alloc_buffer_cb, on_inbound_read_cb);
	trace("on_inbound_listen_cb new connection, conn_context_count:%d", conn_context_count);
}

// 接收 SOCKS5 Hello 包 (阶段 0)
void do_inbound_handshake(conn_context_t* tunnel, socket_ctx_t* socket) {
	trace("do_inbound_handshake.");
	struct s5_ctx* parser = s5_ctx_create();
	uint8_t* data = (uint8_t*)socket->buf.base;
	size_t size = (size_t)socket->buf_len;
	enum s5_result  result = s5_parse(parser, &data, &size); // 解析 SOCKS5 握手包
	if (result == s5_result_need_more) {
		return; // 需要更多数据，等待下次读取
	}
	// SOCKS5 握手成功，返回选择无认证 (\5\0)
	tunnel->stage = tunnel_stage_s5_connrequest;
	socket_ctx_write(socket, "\5\0", 2);
}

// 接收 SOCKS5 请求地址包 (阶段 1)
void do_inbound_handshake_connvps(conn_context_t* tunnel, socket_ctx_t* socket) {
	struct s5_ctx* parser = s5_ctx_create();
	uint8_t* data = (uint8_t*)socket->buf.base;
	size_t size = (size_t)socket->buf_len;
	enum s5_result  result = s5_parse(parser, &data, &size); // 解析 SOCKS5 连接请求包
	if (result == s5_result_need_more) {
		trace("do_inbound_handshake_connvps  s5_result_need_more");
		return;
	}
	// 保存目标地址包，后续通过 TLS 发送到 VPS
	tunnel->target_address_pkg = uv_buf_init((char*)malloc(size), size);
	memcpy(tunnel->target_address_pkg.base, data, size);
	// 连接 VPS 服务器 (远程服务器)
	uv_loop_t *loop = uv_default_loop();
	tunnel->output_handle = (uv_tcp_t*)malloc(sizeof(uv_tcp_t));
	uv_tcp_init(loop, tunnel->output_handle);
	tunnel->output_handle->data = (void*)tunnel; // 绑定上下文
	tunnel->ssl_ctx.private_state = 0; // mbedtls_ssl_init 会设置
	uv_connect_t *connect_req = (uv_connect_t *)malloc(sizeof(uv_connect_t));
	connect_req->data = tunnel;
	struct sockaddr_in dest;
	// 解析远程服务器地址
	uv_ip4_addr(my_config->remote_host, my_config->remote_port, &dest);
	// 发起连接
	uv_tcp_connect(connect_req, tunnel->output_handle, (const struct sockaddr *)&dest, on_outbound_connect_cb);
	trace("do_inbound_handshake_connvps output flag:%d.", tunnel->output_handle->flags);
}

// 连接远程服务器后才返回 SOCKS5 确认给发起端 (阶段 3)
void do_inbound_handshake_comfirm(conn_context_t* tunnel, socket_ctx_t* socket) {
	trace("do_s5_handshake_comfirm");
#ifdef FAKE_APPLICATION
	char * data = socket->buf.base + 5;
#else
	char * data = socket->buf.base;
#endif
	if ( strncmp( data, "connect target is ok", 20) == 0) {
		tunnel->stage = tunnel_stage_streaming; // 进入数据转发阶段
		socket_ctx_t s5ctx;
		s5ctx.handle = tunnel->input_handle;
		socket_ctx_write(&s5ctx, "\5\0\0\1\0\0\0\0\0\0", 10);		// 返回 SOCKS5 确认包
	}
}

//////////////////////////////////////////// tls //////////////////////////////////////////////////////////////////

// 释放 TLS (远程服务器) 连接资源回调
void on_outbound_close_cb(uv_handle_t *handle) {
	conn_context_t *conn_ctx = (conn_context_t *)handle->data;
	trace("on_outbound_close_cb output flag:%d.", conn_ctx->output_handle->flags);
	// 释放远程读取缓冲区
	if (conn_ctx->output_read_buffer) {
		free(conn_ctx->output_read_buffer);
		conn_ctx->output_read_buffer = NULL;
	}
	// 释放远程 handle
	free(conn_ctx->output_handle);
	conn_ctx->output_handle = NULL;
	conn_ctx->stage = tunnel_stage_shutdown;
	// 切换到关闭阶段，触发资源清理
	tunnel_dispatcher(conn_ctx, handle->data);
}

// 新添加的 mbedTLS 接收超时回调函数 (实际只调用 my_mbedtls_recv)
int my_mbedtls_recv_timeout(void *ctx, unsigned char *buf, size_t len, uint32_t timeout) {
	//trace("my_mbedtls_recv_timeout len:%d  to:%d", len, timeout);
	return my_mbedtls_recv(ctx, buf, len);
}

// tls 的读数据回调，当有新数据到达时调用 (来自远程服务器/VPS)
void on_outbound_read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
	conn_context_t *conn_ctx = (conn_context_t *)stream->data;
	if (nread > 0) {
		hex_trace("on_outbound_read_cb", buf->base, nread);
		// TLSinTLS处理: 如果处于 streaming 阶段且已标记为 TLS-in-TLS 转发
		if (conn_ctx->stage == tunnel_stage_streaming && conn_ctx->is_handle_tlsintls) {
			socket_ctx_t  ctx;
			ctx.buf = uv_buf_init(buf->base, nread);
			ctx.buf_len = nread;
			ctx.handle = conn_ctx->output_handle; // 注意：这里使用了 output_handle，但数据应该发给 input_handle
			tunnel_dispatcher(conn_ctx, &ctx); // 调度器将根据 handle 判断转发目标
			conn_ctx->output_read_buffer_len = 0; // 直接转发，无需缓存
			return;
		}

		// 非 TLS-in-TLS 或握手阶段：缓存数据以供 mbedTLS 读取
		size_t new_buffer_len = conn_ctx->output_read_buffer_len + nread;
		unsigned char *new_buffer = (unsigned char *)realloc(conn_ctx->output_read_buffer, new_buffer_len);
		if (new_buffer == NULL) {
			trace("alloc memery fail.");
			return;
		}

		// 将新数据拷贝到缓存的末尾
		conn_ctx->output_read_buffer = new_buffer;
		memcpy(conn_ctx->output_read_buffer + conn_ctx->output_read_buffer_len, buf->base, nread);
		conn_ctx->output_read_buffer_len = new_buffer_len;
		free(buf->base);

		//连接请求处理
		if (conn_ctx->stage == tunnel_stage_s5_connrequest) {
			int status = mbedtls_ssl_handshake_workstatus(&conn_ctx->ssl_ctx);
			rtrace("on_outbound_read_cb mbedtls_ssl_handshake_workstatus:%d .", status);
			if ( status == 2 || status == 5 || status == 19) {
				conn_ctx->stage = tunnel_stage_tls_handshaked;
				socket_ctx_t  ctx;
				ctx.buf_len = 0;
				ctx.handle = conn_ctx->output_handle;
				conn_ctx->output_read_buffer_len = 0;
				tunnel_dispatcher(conn_ctx, &ctx);
			}
			return;
		}

		//直到收到：connect target is ok.
		if (conn_ctx->stage == tunnel_stage_indicate_target) {
			socket_ctx_t  ctx;
			ctx.buf = uv_buf_init((char*)conn_ctx->output_read_buffer, conn_ctx->output_read_buffer_len);
			ctx.buf_len = conn_ctx->output_read_buffer_len;
			ctx.handle = conn_ctx->output_handle;
			conn_ctx->output_read_buffer_len = 0;
			tunnel_dispatcher(conn_ctx, &ctx);
			return;
		}

		//透传过程
		if (conn_ctx->stage == tunnel_stage_streaming) {
			socket_ctx_t  ctx;
			ctx.buf = uv_buf_init((char*)conn_ctx->output_read_buffer, conn_ctx->output_read_buffer_len);
			ctx.buf_len = conn_ctx->output_read_buffer_len;
			ctx.handle = conn_ctx->output_handle;
			conn_ctx->output_read_buffer_len = 0;
			tunnel_dispatcher(conn_ctx, &ctx); 
			return;
		}


		// 普通协议处理 (握手后，读取应用层数据)
//		int ret;
//		unsigned char app_data[65530];
//		do {
//			ret = mbedtls_ssl_read(&conn_ctx->ssl_ctx, app_data, sizeof(app_data)); // 解密数据
//			if (ret > 0) {
//				app_data[ret] = 0;
//				hex_trace("mbedtls_ssl_read", app_data, ret);
//				socket_ctx_t  ctx;
//				ctx.buf = uv_buf_init((char*)app_data, ret);
//				ctx.buf_len = ret;
//				ctx.handle = conn_ctx->output_handle;
//				tunnel_dispatcher(conn_ctx, &ctx); // 将解密后的数据转发给 SOCKS5 客户端
//
//#ifdef TLSINTLS_HANDLE
//				// 识别 Target Server HelloDone，并切换到 TLS-in-TLS 模式 (直接转发 TLS 记录)
//				if (!conn_ctx->is_handle_tlsintls &&  ret >= 9) {
//					char * data = (char*)&app_data[ret - 9];
//					// 假设 TLS Server HelloDone 报文尾部特征：ChangeCipherSpec(0x14) + EncryptedHandshakeMessage(0x16)
//					// 或者更可能是： Handshake (0x16) + Version (0x0303) + Length (2bytes) + ServerHelloDone (0x0E)
//					// 这里检查了数据的最后9个字节，且 data[0] == 0x16 (Handshake) 和 data[5] == 0x0E (Server Hello Done)
//					// 这是一个针对特定协议/实现的判断，用于在隧道内识别目标 TLS 握手结束
//					if (data[0] == 0x16 && data[5] == 0x0E) {
//						trace("recv target Server HelloDone, Identify as TLS packets and forward directly.");
//						conn_ctx->is_handle_tlsintls = true; // 开启 TLS-in-TLS 转发
//					}
//				}
//#endif
//			}
//			else if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
//				//trace("on_outbound_read_cb MBEDTLS_ERR_SSL_WANT_READ %d", ret);
//			}
//			else if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || ret < 0 || ret == 0) {
//				// 对端关闭或错误
//				break;
//			}
//		} while (ret > 0);
//		return;
	}
	else if (nread == UV_EOF || nread < 0) {
		// 对端关闭或错误，关闭连接
		trace("on_outbound_read_cb err: %s", uv_strerror((int)nread));
		uv_close((uv_handle_t*)stream, on_outbound_close_cb);
	}
}

// mbedTLS 随机数生成回调 (⚠️ 警告: 测试/示例代码，使用了硬编码的 13，非安全随机数)
int my_mbedtls_ctr_drbg_random(void *p_rng, unsigned char *output, size_t output_len)
{
	int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
	mbedtls_ctr_drbg_context *ctx = (mbedtls_ctr_drbg_context *)p_rng;
	// 实际应使用 mbedtls_platform_random() 或硬件特有代码
	for (size_t i = 0; i < output_len; i++) {
		// ⚠️ 在非测试环境中，请勿使用 C 标准库的 rand()
		output[i] =  (unsigned char)(rand() % 256); // 简单硬编码，用于非安全测试
	}
	return 0;
}

// mbedTLS Session Cache 获取回调 (当前实现为返回 0，表示没有缓存)
int my_cache_get(void *data, unsigned char const *session_id, size_t session_id_len, mbedtls_ssl_session *session) {
	// 在这里实现从缓存中获取会话数据的逻辑
	// 如果找到会话，返回 0；否则返回 -1 (这里直接返回0可能导致意想不到的行为，应该返回-1)
	return 0;
}

// mbedTLS Session Cache 设置回调 (当前实现为返回 0，表示成功)
int my_cache_set(void *data, unsigned char const *session_id, size_t session_id_len, const mbedtls_ssl_session *session) {
	// 在这里实现将会话数据存储到缓存的逻辑
	// 返回 0 表示成功，非0表示失败
	return 0;
}

// TLS连接回调 (远程服务器连接成功)
void on_outbound_connect_cb(uv_connect_t *req, int status) {
	conn_context_t *conn_ctx = (conn_context_t *)req->data;
	if (status < 0) {
		trace("on_outbound_connect_cb conn vpn service fail: %s", uv_strerror(status));
		// 连接失败，关闭 SOCKS5 客户端连接
		if (conn_ctx->input_handle && !uv_is_closing((uv_handle_t*)conn_ctx->input_handle)) {
			uv_close((uv_handle_t*)conn_ctx->input_handle, on_inbound_close_cb);
		}
		return;
	}

	const char *pers = "ssl_client1";
	// 初始化 mbedTLS 上下文
	mbedtls_ssl_init(&conn_ctx->ssl_ctx);
	mbedtls_ssl_config_init(&conf);
	mbedtls_x509_crt_init(&cacert);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	// 播种 CTR_DRBG
	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));

	// 初始化 Session Cache
	//mbedtls_ssl_cache_context cache;
	//mbedtls_ssl_conf_session_tickets(&conf, MBEDTLS_SSL_SESSION_TICKETS_ENABLED); // 启用 session tickets
	//mbedtls_ssl_cache_init(&cache); // 初始化 session cache
	//mbedtls_ssl_cache_set_max_entries(&cache, 100); // 设置最大条目数
	//mbedtls_ssl_conf_session_cache(&conf, (void*)&cache, my_cache_get, my_cache_set); // 设置 session cache 的回调函数

	int ret = 0;
	// 使用自带的测试证书 (CA 证书)
	//int ret = mbedtls_x509_crt_parse(&cacert, (const unsigned char *)c_mbedtls_test_cas_pem, strlen(c_mbedtls_test_cas_pem) + 1);
	//if (ret != 0) { fprintf(stderr, "crt_parse failed: %d\n", ret); return; }
	// 设置默认配置为客户端模式
	mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);

	// 强制限制为 TLS 1.2:
	//mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3); // TLS 1.2
	//mbedtls_ssl_conf_max_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3); // TLS 1.2

	// 强制限制为 TLS 1.3: (当前被注释)
	//mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4); // TLS 1.3
	//mbedtls_ssl_conf_max_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4); // TLS 1.3

	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE); // **不验证**服务器证书 (MBEDTLS_SSL_VERIFY_NONE)
	//mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL); // 设置 CA 证书链
	mbedtls_ssl_conf_rng(&conf, my_mbedtls_ctr_drbg_random, &ctr_drbg);  // 设置随机数生成器

	mbedtls_ssl_setup(&conn_ctx->ssl_ctx, &conf);
	mbedtls_ssl_set_hostname(&conn_ctx->ssl_ctx, "baidu.com"); // 设置 SNI 主机名

	// 设置底层 socket (使用自定义的 send/recv 回调)
	mbedtls_ssl_set_bio(&conn_ctx->ssl_ctx, conn_ctx, my_mbedtls_send, my_mbedtls_recv, my_mbedtls_recv_timeout);

	// 设置 Session ID，用于自定义的身份验证/会话重用机制
	if (!had_verified) {
		struct session_id sid;
		create_session_id(&sid, 0, my_authinfo_md5); // 第一次连接使用 '0' 标记
		ret = mbedtls_ssl_set_sessionid(&conn_ctx->ssl_ctx, (unsigned char*)&sid);
	}
	else {
		struct session_id sid;
		create_session_id(&sid, 1, my_authinfo_md5); // 非第一次连接使用 '1' 标记
		ret = mbedtls_ssl_set_sessionid(&conn_ctx->ssl_ctx, (unsigned char*)&sid);
	}

	// 启动读事件，驱动 TLS 握手 (第一次尝试握手)
	ret = mbedtls_ssl_handshake(&conn_ctx->ssl_ctx);
	if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
		uv_read_start((uv_stream_t *)conn_ctx->output_handle, alloc_buffer_cb, on_outbound_read_cb); // 开始读取远程数据
	}
	else if (ret != 0) {
		// 初始握手错误，关闭连接
		char error_buf[256];
		mbedtls_strerror(ret, error_buf, sizeof(error_buf));
		fprintf(stderr, "Initial Handshake Error: %s (-0x%04x)\n", error_buf, -ret);
		uv_close((uv_handle_t*)&conn_ctx->output_handle, NULL);
	}
	free(req);
}

// mbedTLS 的发送回调函数，将数据写入 libuv 流
int my_mbedtls_send(void *ctx, const unsigned char *buf, size_t len) {
	conn_context_t *conn_ctx = (conn_context_t *)ctx;
	uv_write_t *req = (uv_write_t *)malloc(sizeof(uv_write_t));
	uv_buf_t write_buf = uv_buf_init((char *)buf, len);
	// mbedTLS 内部会管理 buf 的生命周期，这里 req->data 不指向数据
	req->data = NULL;  //这里不能指向数据，mbedtls内部对数据进行释放
	// 异步写入数据到远程服务器
	int ret = uv_write(req, (uv_stream_t *)conn_ctx->output_handle, &write_buf, 1, socket_write_done_cb);
	hex_trace("my_mbedtls_send", buf, len);
	return (int)len; // 必须返回成功写入的字节数
}

// 将 SSL 缓存数据全部发送完成 (循环调用 mbedtls_ssl_write 直到数据发完)
int mbedtls_ssl_write_all(mbedtls_ssl_context *ssl, const unsigned char *buf, size_t len) {
	int ret = 0;
	size_t sent = 0;
	hex_trace("mbedtls_ssl_write_all", buf, len);
	do {
		ret = mbedtls_ssl_write(ssl, buf + sent, len - sent);
		char error_buf[256];
		mbedtls_strerror(ret, error_buf, sizeof(error_buf));
		// fprintf(stderr, "Initial Handshake Error: %s ret:%d\n", error_buf,ret); // 似乎是错误的输出信息
		if (ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
			continue; // 需要等待写入就绪
		}if (ret < 0) {
			trace("do_data_forword ret:%d", ret);
			break; // 写入失败
		}
		sent += ret;
	} while (sent < len);
	return ret; // 返回最后一次 mbedtls_ssl_write 的结果
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
	uv_buf_t write_buf = uv_buf_init(app_data, len+5);
	int ret = uv_write(req, (uv_stream_t *)conn_ctx->output_handle, &write_buf, 1, socket_write_done_cb);
	hex_trace("fake_mbedtls_send", app_data, len + 5);
#else
	char *  app_data = (char*)malloc(len);
	memcpy(app_data, buf, len);
	uv_write_t *req = (uv_write_t *)malloc(sizeof(uv_write_t));
	req->data = (void*)app_data;
	uv_buf_t write_buf = uv_buf_init(app_data, len);
	int ret = uv_write(req, (uv_stream_t *)conn_ctx->output_handle, &write_buf, 1, socket_write_done_cb);
	hex_trace("fake_mbedtls_send", app_data, len);
#endif
	return (int)len; // 必须返回成功写入的字节数
}

// mbedTLS 的接收回调函数，从我们自己的缓存中读取数据
int my_mbedtls_recv(void *ctx, unsigned char *buf, size_t len) {
	//hex_trace("my_mbedtls_recv", buf, len);
	conn_context_t *conn_ctx = (conn_context_t *)ctx;
	// 检查缓存中是否有数据可读
	size_t available_data = conn_ctx->output_read_buffer_len - conn_ctx->output_read_buffer_offset;
	if (available_data == 0) {
		// 缓存为空，需要更多数据
		//trace("my_mbedtls_recv MBEDTLS_ERR_SSL_WANT_READ");
		return MBEDTLS_ERR_SSL_WANT_READ;
	}
	// 确定本次要读取的字节数, 从缓存中拷贝数据到 mbedTLS 提供的缓冲区，更新偏移量
	size_t bytes_to_read = (len < available_data) ? len : available_data;
	memcpy(buf, conn_ctx->output_read_buffer + conn_ctx->output_read_buffer_offset, bytes_to_read);
	conn_ctx->output_read_buffer_offset += bytes_to_read;

	// 如果所有缓存的数据都已消费，则重置缓存
	if (conn_ctx->output_read_buffer_offset == conn_ctx->output_read_buffer_len) {
		free(conn_ctx->output_read_buffer);
		conn_ctx->output_read_buffer = NULL;
		conn_ctx->output_read_buffer_len = 0;
		conn_ctx->output_read_buffer_offset = 0;
	}
	return (int)bytes_to_read;
}

// 握手后第一个数据包发送 (目标地址信息 + 身份验证信息) (阶段 2)
void do_tls_addressinfo_data(conn_context_t* tunnel, socket_ctx_t* socket) {
	trace("do_tls_addressinfo_data");
	if (had_verified) {
		// 已验证，只发送目标地址包 (用于会话重用)
		//mbedtls_ssl_write_all(&tunnel->ssl_ctx, (const unsigned char *)tunnel->target_address_pkg.base, tunnel->target_address_pkg.len);
		fake_mbedtls_send(tunnel, (const unsigned char *)tunnel->target_address_pkg.base, tunnel->target_address_pkg.len);
	}
	else {
		// 首次连接，构造包含目标地址包和身份验证信息的完整数据包
		size_t data_len = tunnel->target_address_pkg.len + sizeof(auth_info_t);
		char * data = (char*)malloc(data_len);
		memcpy(data, tunnel->target_address_pkg.base, tunnel->target_address_pkg.len);
		struct auth_info authinfo;
		memset(&authinfo, 0x00, sizeof(auth_info_t));
		// 填充身份验证信息
		authinfo.app_type = my_config->app_type;
		authinfo.user_id = my_config->user_id;
		string_to_uuid(my_config->user_name, authinfo.user_name);
		string_to_uuid(my_config->user_cipher, authinfo.user_cipher);
		memcpy(data + tunnel->target_address_pkg.len, (void*)&authinfo, sizeof(auth_info_t));
		// 通过 TLS 发送
		//mbedtls_ssl_write_all(&tunnel->ssl_ctx, (const unsigned char *)data, data_len);
		fake_mbedtls_send(tunnel, (const unsigned char *)data, data_len);
		had_verified = true; // 标记已验证
		free(data);
	}
	// 发送目标地址包后，等待服务器返回 SOCKS5 确认
	tunnel->stage = tunnel_stage_indicate_target;
}

// tls 数据传输，包括 IN/OUT (阶段 4)
void do_data_forword(conn_context_t* tunnel, socket_ctx_t* socket) {
	uint8_t* data = (uint8_t*)socket->buf.base;
	size_t size = (size_t)socket->buf_len;
#ifdef _WIN32
	if (socket->handle->socket == tunnel->output_handle->socket) { // 检查数据是否来自远程服务器
#else
	if (socket->handle->u.fd == tunnel->output_handle->u.fd) {
#endif
		if (tunnel->input_handle) {
#ifdef FAKE_APPLICATION
			size_t s5_data_len = size - 5;
			uv_write_t* req = (uv_write_t*)calloc(1, sizeof(uv_write_t));
			req->data = (char*)malloc(s5_data_len);
			memcpy(req->data, data+5, s5_data_len);
			uv_buf_t buf = uv_buf_init(req->data, s5_data_len);
			trace("do_data_forword uv_write to vps", req->data, s5_data_len);
			uv_write(req, (uv_stream_t*)tunnel->input_handle, &buf, 1, socket_write_done_cb);
#else
			size_t s5_data_len = size;
			uv_write_t* req = (uv_write_t*)calloc(1, sizeof(uv_write_t));
			req->data = (char*)malloc(s5_data_len);
			memcpy(req->data, data, s5_data_len);
			uv_buf_t buf = uv_buf_init(req->data, s5_data_len);
			trace("do_data_forword uv_write to vps", req->data, s5_data_len);
			uv_write(req, (uv_stream_t*)tunnel->input_handle, &buf, 1, socket_write_done_cb);
#endif
			return;
		}
	}

#ifdef _WIN32
	else if (socket->handle->socket == tunnel->input_handle->socket) { // 检查数据是否来自 SOCKS5 客户端
#else
	if (socket->handle->u.fd == tunnel->input_handle->u.fd) {
#endif
		// 数据来自 SOCKS5 客户端，需要转发给远程服务器 (VPS)
		if (tunnel->output_handle) {
			//if (tunnel->is_handle_tlsintls) {
			//	// TLS-in-TLS 模式：直接发送原始数据 (不加密)
			//	uv_write_t* req = (uv_write_t*)calloc(1, sizeof(uv_write_t));
			//	req->data = (char*)malloc(size); // 复制数据
			//	memcpy(req->data, data, size);
			//	uv_buf_t buf = uv_buf_init(data, (unsigned int)size);
			//	trace("do_data_forword uv_write to vps", data, size);
			//	uv_write(req, (uv_stream_t*)tunnel->output_handle, &buf, 1, socket_write_done_cb);
			//}
			//else {
			//	// 普通模式：通过 mbedTLS 加密发送
			//	trace("do_data_forword mbedtls_ssl_write to vps", data, size);
			//	mbedtls_ssl_write(&tunnel->ssl_ctx, data, size);
			//}
			fake_mbedtls_send( tunnel, data, size);
			return;
		}
	}
	hex_trace("do_data_forword handless", data, size); // 无法识别来源或处理
	}

// 关闭通道，只有 input 和 output 都断开后才释放通道 (阶段 5)
void do_stage_shutdown(conn_context_t* tunnel, socket_ctx_t* socket) {
	// 确保 input_handle 关闭
	if (tunnel->input_handle) {
		trace("do_stage_shutdown to close input");
		if (!uv_is_closing((uv_handle_t*)tunnel->input_handle)) {
			uv_close((uv_handle_t*)tunnel->input_handle, on_inbound_close_cb);
			return; // 等待回调释放资源
		}
	}
	// 确保 output_handle 关闭
	else if (tunnel->output_handle) {
		trace("do_stage_shutdown to close output");
		if (!uv_is_closing((uv_handle_t*)tunnel->output_handle)) {
			uv_close((uv_handle_t*)tunnel->output_handle, on_outbound_close_cb);
			return; // 等待回调释放资源
		}
	}
	// 只有 input 和 output 都为 NULL 时，才释放 conn_context
	if (tunnel->input_handle == tunnel->output_handle) { // 此时两者应都为 NULL
		conn_context_count--;
		mbedtls_ssl_free(&tunnel->ssl_ctx);
		trace("do_stage_shutdown conn_context_count:%d", conn_context_count);
		free(tunnel);
	}
}

// dispath (隧道状态机调度函数)
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
	case tunnel_stage_indicate_target: // 3: 发送目标地址后，等待 VPS 确认
		do_inbound_handshake_comfirm(tunnel, socket);
		break;
	case tunnel_stage_streaming: // 4: 数据转发
		do_data_forword(tunnel, socket);
		break;
	case tunnel_stage_shutdown: // 5: 关闭连接/资源清理
		do_stage_shutdown(tunnel, socket);
		break;
	}
}

// 开始 Socks5 本地监听及 LOOP 开启线程函数
void * uv_loop_thread_function(void* arg) {
	uv_loop_t *loop = (uv_loop_t *)arg;
	uv_tcp_t server_socket;
	struct sockaddr_in addr;
	uv_tcp_init(loop, &server_socket);
	// 绑定本地监听地址和端口
	uv_ip4_addr(my_config->local_host, my_config->local_port, &addr);
	uv_tcp_bind(&server_socket, (const struct sockaddr*)&addr, 0);
	// 开始监听
	int r = uv_listen((uv_stream_t*)&server_socket, 128, on_inbound_listen_cb);
	trace("start socks5 server listening on:%d error:%s", my_config->local_port, uv_strerror(r));
	// 运行事件循环
	uv_run(loop, UV_RUN_DEFAULT);
	return 0;
}

// 信号处理回调 (用于处理退出信号，如 Ctrl+C)
void on_signal(uv_signal_t* handle, int signum) {
	uv_loop_t *loop = (uv_loop_t*)handle->data;
	uv_stop(loop); // 停止 libuv 事件循环
}

// main 主函数
int main(int argc, char * argv[]) {
	fprintf(stderr, "reality - client.\n");
	my_config = configure_create(argc, argv); // 加载配置

	// 初始化身份验证信息并计算 MD5
	my_authinfo.app_type = my_config->app_type;
	my_authinfo.user_id = my_config->user_id;
	string_to_uuid(my_config->user_name, my_authinfo.user_name);
	string_to_uuid(my_config->user_cipher, my_authinfo.user_cipher);
	mbedtls_md5((uint8_t *)&my_authinfo, sizeof(struct auth_info), (uint8_t *)my_authinfo_md5);

	// uv thread
	pthread_t thread_uv;
	uv_loop_t *loop = uv_default_loop();

	// exit signal & main thread
	uv_signal_t sig;
	uv_signal_init(loop, &sig);
	sig.data = (void*)loop;
	uv_signal_start(&sig, on_signal, SIGINT); // 监听 Ctrl+C 信号

	// 创建并启动 libuv 事件循环线程
	if (pthread_create(&thread_uv, NULL, uv_loop_thread_function, (void*)loop) != 0) {
		fprintf(stderr, "pthread_create");
		return 1;
	}

	// main thread and user command (主线程用于接收用户命令)
	while (1) {
		static char sz[256] = { 0 };
		if (fgets(sz, 256, stdin) == NULL)
			continue;
		else if (strcmp(sz, "exit\n") == 0) {
			// 接收到 exit 命令，触发信号处理关闭 loop
			uv_signal_start_oneshot(&sig, on_signal, 0);
			break;
		}
	}

	// 关闭 libuv loop 资源
	uv_loop_close(loop);
	// 释放配置资源
	configure_destroy(my_config);
	exit(0);
	return 0;
}