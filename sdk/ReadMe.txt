1. linux系统编译
cd build
cmake ..
make
生成的so及测试程序位于output目录下。
运行测试程序依赖openssl、mosquitto、pthread库。

2. windows系统编译
使用Microsoft Visual Studio 2013及以上版本编译解决方案。
运行测试程序依赖openssl、mosquitto、pthread-win32库。

3. 运行测试程序前请先准备好设备私钥文件mcu_priv_key.pem