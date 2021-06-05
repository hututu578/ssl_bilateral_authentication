/*
参考链接：https://www.cnblogs.com/lsdb/p/9391979.html
执行命令：./server 7838 1 server.crt server.key ca.crt
*/
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
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
	
	//获取证书并返回X509操作句柄
    cert = SSL_get_peer_certificate(ssl);
    // SSL_get_verify_result()是重点，SSL_CTX_set_verify()只是配置启不启用并没有执行认证，调用该函数才会真证进行证书认证
    // 如果验证不通过，那么程序抛出异常中止连接
    if(SSL_get_verify_result(ssl) == X509_V_OK){
        printf("收到client X509证书\n");
    }
	else{
		printf("未收到client X509证书\n");
		return ERR;
	}
    if (cert != NULL) {
        printf("client数字证书信息:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("证书: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("颁发者: %s\n\n", line);
        free(line);
        X509_free(cert);
		printf("对client证书验证通过!!!\n");
    } 
	else{
        printf("无证书信息,对client证书验证失败!!!\n");
		return ERR;
	}
	return OK;
}

int main(int argc, char **argv) 
{
    int sockfd, new_fd;
    socklen_t len;
    struct sockaddr_in my_addr, their_addr;
    unsigned int myport, lisnum;
    char send_buf[MAXBUF + 1];
	char recv_buf[MAXBUF + 1];
    SSL_CTX *ctx;
	
	//判断参数个数是否正确
	if(argc != 6)
	{
		printf("usage: %s ser_port lis_num ser_crt ser_key ca_crt\n",argv[0]);
		return -1;
	}
	//获取port端口号，如果没指定则default=7838
    if (argv[1])
        myport = atoi(argv[1]);
    else
        myport = 7838;
	
	//设置最大监听数量，如果没有指定则default=2
    if (argv[2])
        lisnum = atoi(argv[2]);
    else
        lisnum = 2;
	/**************************************第一步：OPENSSL初始化**********************************/
    /* SSL 库初始化 */
    SSL_library_init();
    /* 载入所有 SSL 算法 */
    OpenSSL_add_all_algorithms();
    /* 载入所有 SSL 错误消息 */
    SSL_load_error_strings();
    /* 以 SSL V2 和 V3 标准兼容方式产生一个 SSL_CTX ，即 SSL Content Text */
    ctx = SSL_CTX_new(SSLv23_server_method());
    /* 也可以用 SSLv2_server_method() 或 SSLv3_server_method() 单独表示 V2 或 V3标准 */
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
    /* 开启一个 socket 监听 */
    if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    } else
        printf("socket created success!\n");

    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = PF_INET;
    my_addr.sin_port = htons(myport);
    my_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sockfd, (struct sockaddr *) &my_addr, sizeof(struct sockaddr))== -1) {
        perror("bind");
        exit(1);
    } else
        printf("binded success!\n");

    if (listen(sockfd, lisnum) == -1) {
        perror("listen");
        exit(1);
    } else
        printf("begin listen,waitting for client connect...\n");

	SSL *ssl;
	len = sizeof(struct sockaddr);
	/* 等待客户端连上来 */
	if ((new_fd = accept(sockfd, (struct sockaddr *) &their_addr, &len))
			== -1) {
		perror("accept");
		exit(errno);
	} else
		printf("server: got connection from %s, port %d, socket %d\n",
				inet_ntoa(their_addr.sin_addr), ntohs(their_addr.sin_port),
				new_fd);
				
	/**************************************第三步：将普通socket与SSL绑定，在SSL层建立连接*******************************/
	/* 基于 ctx 产生一个新的 SSL */
	ssl = SSL_new(ctx);
	/* 将连接用户的 socket 加入到 SSL */
	SSL_set_fd(ssl, new_fd);
	/* 建立 SSL 连接 */
	if (SSL_accept(ssl) == -1) {
		perror("accept");
		printf("SSL 连接失败!\n");
		close(new_fd);
		goto end;
	}
	/**************************************第四步：验证client客户端的证书*******************************/
	if(ShowCerts(ssl) == ERR)goto end;

	/**************************************第五步：https进行收发数据*******************************/
	while(1)
	{	
		/* SSL_read接收客户端的消息 */
		printf("等待客户端发送过来的消息：\n");
		len = SSL_read(ssl, recv_buf, MAXBUF);
		if (len > 0)
			printf("接收client消息成功:'%s'，共%d个字节的数据\n", recv_buf, len);
		else{
			printf("消息接收失败！错误代码是%d，错误信息是'%s'\n",errno, strerror(errno));
			break;          //退出通信
		}
		memset(recv_buf,0,sizeof(recv_buf));   //清空接收缓存区
		/* SSL_write发消息给客户端 */
		printf("请输入要发送给客户端的内容：\n");
		scanf("%s",send_buf);
		if(!strncmp(send_buf,"+++",3))break;    //收到+++表示退出
		len = SSL_write(ssl, send_buf, strlen(send_buf));
		if (len <= 0) {
			printf("消息'%s'发送失败！错误代码是%d，错误信息是'%s'\n", send_buf, errno,strerror(errno));
			break;
		} else
			printf("消息'%s'发送成功，共发送了%d个字节！\n", send_buf, len);
		memset(send_buf,0,sizeof(send_buf));   //清空接收缓存区
	}
	/**************************************第六步：关闭连接及资源清理*******************************/
	/* 处理每个新连接上的数据收发结束 */
end:
	/* 关闭 SSL 连接 */
	SSL_shutdown(ssl);
	/* 释放 SSL */
	SSL_free(ssl);
	/* 关闭 socket */
	close(new_fd);
    /* 关闭监听的 socket */
    close(sockfd);
    /* 释放 CTX */
    SSL_CTX_free(ctx);
    return 0;
}