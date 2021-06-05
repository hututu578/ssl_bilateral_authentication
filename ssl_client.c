/*
参考链接：https://www.cnblogs.com/lsdb/p/9391979.html
执行命令：./client 127.0.0.1 7838 client.crt client.key ca.crt
*/
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <resolv.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define OK 0
#define ERR 1

#define MAXBUF 1024

#define CACERT "ca.crt"		//定义CA根证书存放路径

//进行证书认证并打印证书相关信息
//return:OK表示证书验证成功，ERR表示证书验证失败
int ShowCerts(SSL * ssl)
{
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    // SSL_get_verify_result()是重点，SSL_CTX_set_verify()只是配置启不启用并没有执行认证，调用该函数才会真证进行证书认证
    // 如果验证不通过，那么程序抛出异常中止连接
    if(SSL_get_verify_result(ssl) == X509_V_OK){
        printf("收到server X509证书\n");
    }
	else{
		printf("未收到server X509证书\n");
		return ERR;
	}
    if (cert != NULL) {
        printf("server数字证书信息:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("证书: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("颁发者: %s\n\n", line);
        free(line);
        X509_free(cert);
		printf("对server证书验证通过!!!\n");
    } 
	else{
		printf("无证书信息,对server证书验证失败!!!\n");
		return ERR;
	}
	return OK;
}

int main(int argc, char **argv)
{
    int sockfd, len;
    struct sockaddr_in dest;
    char send_buffer[MAXBUF + 1];
	char recv_buffer[MAXBUF + 1];
    SSL_CTX *ctx;
    SSL *ssl;

	//判断参数个数是否正确
	if(argc != 6)
	{
		printf("usage: %s ser_ip ser_port cli_crt cli_key ca_crt\n",argv[0]);
		return -1;
	}
	
    // if (argc != 5) {
        // printf("参数格式错误！正确用法如下：\n\t\t%s IP地址 端口\n\t比如:\t%s 127.0.0.1 80\n此程序用来从某个"
             // "IP 地址的服务器某个端口接收最多 MAXBUF 个字节的消息",
             // argv[0], argv[0]);
        // exit(0);
    // }
	
	/**************************************第一步：OPENSSL初始化**********************************/
    /* SSL 库初始化，参看 ssl-server.c 代码 */
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    // 双向验证
    // SSL_VERIFY_PEER---要求对证书进行认证，没有证书也会放行
    // SSL_VERIFY_FAIL_IF_NO_PEER_CERT---要求客户端需要提供证书，但验证发现单独使用没有证书也会放行
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    // 设置信任根证书
    if (SSL_CTX_load_verify_locations(ctx, argv[5],NULL)<=0){
        ERR_print_errors_fp(stdout);
        exit(1);
    }

    /* 载入用户的数字证书， 此证书用来发送给客户端。 证书里包含有公钥 */
    if (SSL_CTX_use_certificate_file(ctx, argv[3], SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 载入用户私钥 */
    if (SSL_CTX_use_PrivateKey_file(ctx, argv[4], SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }
    /* 检查用户私钥是否正确 */
    if (!SSL_CTX_check_private_key(ctx)) {
        ERR_print_errors_fp(stdout);
        exit(1);
    }

	/**************************************第二步：普通socket建立连接*******************************/
    /* 创建一个 socket 用于 tcp 通信 */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket");
        exit(errno);
    }
    printf("socket created success!\n");

    /* 初始化服务器端（对方）的地址和端口信息 */
    bzero(&dest, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(atoi(argv[2]));
    if (inet_aton(argv[1], (struct in_addr *) &dest.sin_addr.s_addr) == 0) {
        perror(argv[1]);
        exit(errno);
    }
    printf("address created success!\n");

    /* 连接服务器 */
    if (connect(sockfd, (struct sockaddr *) &dest, sizeof(dest)) != 0) {
        perror("Connect ");
        exit(errno);
    }
    printf("server connected  success!\n");

	/**************************************第三步：将普通socket与SSL绑定，在SSL层建立连接*******************************/
    /* 基于 ctx 产生一个新的 SSL */
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sockfd);
    /* 建立 SSL 连接 */
    if (SSL_connect(ssl) == -1)
	{
        ERR_print_errors_fp(stderr);
		printf("SSL 连接失败!\n");
		goto end;
	}
    else {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
	/**************************************第四步：验证server服务端的证书*******************************/
		if(ShowCerts(ssl) == ERR)goto end;
    }
	/**************************************第五步：https进行收发数据*******************************/
	//下面客户端和服务器互相收发
	while(1)
	{
		//使用SSL_write函数发送数据
		printf("请输入要发送给服务器的内容：\n");
		scanf("%s",send_buffer);
		if(!strncmp(send_buffer,"+++",3))break;    //收到+++表示退出
		/* 发消息给服务器 */
		len = SSL_write(ssl, send_buffer, strlen(send_buffer));
		if (len < 0)
			printf("消息'%s'发送失败！错误代码是%d，错误信息是'%s'\n",send_buffer, errno, strerror(errno));
		else
			printf("消息'%s'发送成功，共发送了%d个字节！\n",send_buffer, len);
		memset(send_buffer,0,sizeof(send_buffer));   //清空接收缓存区
		
		
		/* 使用SSL_read函数接收数据，接收对方发过来的消息，最多接收 MAXBUF 个字节 */
		len = SSL_read(ssl, recv_buffer, MAXBUF);
		if (len > 0)
			printf("接收消息成功:'%s'，共%d个字节的数据\n",recv_buffer, len);
		else 
		{
			printf("消息接收失败！错误代码是%d，错误信息是'%s'\n",errno, strerror(errno));
			break;
		}
		memset(recv_buffer,0,sizeof(recv_buffer));   //清空接收缓存区
	}  
  /**************************************第六步：关闭连接及资源清理*******************************/
end:
	/* 关闭连接 */
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    return 0;
}