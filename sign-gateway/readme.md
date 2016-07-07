## 签名代理网关

### 编译打包

	使用以下命令打包
	mvn clean install

### 密钥存放

应将密钥放置在解压运行后的sign-gategway目录下的keys目录.

keys目录中密钥文件命名方式:

somes.pem	公钥文件
somes.pk8	私钥文件
somes.pw	私钥文件的密码. 明文文本保存

**密钥文件更改不需要重启服务**	