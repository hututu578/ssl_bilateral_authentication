#all:client_https.c server_https.c
all:
	gcc ssl_server.c -o server -lssl -lcrypto -ldl -lcurses
	gcc ssl_client.c -o client -lssl -lcrypto -ldl -lcurses
#如果是自定义安装路径的，可以使用下面的
#gcc -Wall -o client client.c -I/usr/openssl-1.0.0c/include/usr/openssl-1.0.0c/libssl.a /usr/openssl-1.0.0c/libcrypto.a –ldl
#gcc -Wall -o server server.c -I/usr/openssl-1.0.0c/include/usr/openssl-1.0.0c/libssl.a /usr/openssl-1.0.0c/libcrypto.a -ldl

clean:
	rm -f client server