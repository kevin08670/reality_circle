# inno-reality
1. 支持TLS1.2、1.3 加密代理传输
2. 支持多域名，多证书部署
3. 支持TlsInTls处理
4. 自适应窃取证书

## 项目介绍
    reality 协议代理方案
  
## git
   git clone https://git.inconnecting.com/iprotocol/inno-reality.git

## 编译
    支持全平台编译
    
### linux, ubuntu
    mkdir build
    cd build
    cmake .. & make
    cmake -D CMAKE_BUILD_TYPE=Release .. && make

### windows
    visual stuido 2015+
    打开 ./win32/realityNative.sln 编译即可

### IOS
    mkdir ios
    cd ios
    cmake .. -G "Xcode" -DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_SYSROOT=iphoneos -DCMAKE_OSX_DEPLOYMENT_TARGET=12.0 -DENABLE_TESTING=OFF -DENABLE_PROGRAMS=OFF -DCMAKE_POLICY_VERSION_MININUM=3.5

### ANDROID
    android
 
## Usage
    ./realityServer
    ./reality -s192.168.1.1 -p443 -fbaidu.com
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



