# ssl_bilateral_authentication    
https bilateral authentication based on openssl   
### 1.概述 
&#8195;&#8195;https基于SSL/TLS提供安全的通信信道，基于证书认证技术实现服务器和客户端之间的身份认证，确保了通信双方身份的可信。另外在双方完成身份认证之后协商出通信密钥，对通信过程中的数据进行加密，采用密文传输的方式进行通信，确保通信过程数据的隐私安全性。    
&#8195;&#8195;openssl工具提供了强大的证书及密码学运算支持，可以很好的实现对证书的操作以及加密处理。本文基于openssl所提供的库函数实现server和client双方的身份认证，并实现https安全通信。完成通信双方的身份认证需要为server和client颁发数字证书，openssl提供了相关操作可以完成自建CA以及证书颁发，详情请见之前的博客：   
<https://blog.csdn.net/weixin_42700740/article/details/117527769>   
&#8195;&#8195;以下会设计ssl_server.c及ssl_ckient.c程序，分别实现服务端和客户端的程序，其中身份认证的流程及可靠通信代码设计关键点如下：    
1.服务端和客户端分别选中各自信任的CA，就是加载CA的证书到程序中。   
2.服务端和客户端分别加载自己的证书和私钥，并验证证书和私钥的匹配性。   
3.server建立socket接口并与SSL绑定，等待客户端连接。    
4.client也建立socket接口并与SSL绑定，请求连接server，并将自己的数字证书发送给server。   
5.server收到client的证书后是要加载的CA信息验证client证书，验证失败直接断开连接，验证成功则继续，并将自家的数字证书发送给client。    
6.client收到server的数字证书后采用同样的方式验证其证书。   
7.双方证书验证通过后顺利建立https连接，可进行socket通信。   
### 2.测试    
1.首先确保openssl工具安装成功。    
2.编译：   
```gcc ssl_server.c -o server -lssl -lcrypto -ldl -lcurses```   
```gcc ssl_client.c -o client -lssl -lcrypto -ldl -lcurses```   
3.server服务端运行：    
```./server 7838 1 server.crt server.key ca.crt```    
其中7838表示server的端口号；1表示socket listen的数量；server.crt表示server证书存放路径；server.key表示server私钥存放路径；ca.crt表示CA根证书存放路径。   
4.client客户端运行：    
```./client 127.0.0.1 7838 client.crt client.key ca.crt```    
其中127.0.0.1表示server的ip地址；7838表示server的端口号；client.crt表示client证书存放路径；client.key表示client私钥存放路径；ca.crt表示CA根证书存放路径。    
5.执行结果    
server端：    
![avatar](https://img-blog.csdnimg.cn/20210605200855132.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MjcwMDc0MA==,size_16,color_FFFFFF,t_70)   
client端：    
![avatar](https://img-blog.csdnimg.cn/2021060520093276.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80MjcwMDc0MA==,size_16,color_FFFFFF,t_70)    
