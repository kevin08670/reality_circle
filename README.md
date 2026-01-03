# inno-reality
1. 支持TLS1.2、1.3 加密代理传输
2. 支持多域名，多证书部署
3. 支持TlsInTls处理

## 项目介绍
    xProxy : inno-reality代理服务器
    xClient: 客户端

## git
   git clone https://git.inconnecting.com/iprotocol/inno-reality.git

## 编译
    支持全平台编译
### linux, ubuntu, macOS
    mkdir build
    cd build
    cmake .. & make
    cmake -D CMAKE_BUILD_TYPE=Release .. && make

### windows 解决方案
    用VC打开 reality.sln 即可,已关连第三方库等
 
## Usage
    ./xProxy
    ./xClient -s192.168.1.1 -p443
### 参数说明

### 测试
    curl --socks5 127.0.0.1:8892 ip-api.com

## xProxy 服务器命令说明

### exit
    退出

### print local
    打印本地认证用户信息列表

### print online
    打印在线用户信息列表



