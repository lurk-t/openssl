#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <stdio.h>
//#include <unistd.h>
#include <io.h>
#include <string.h>
#include <WinSock2.h>
//#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <WS2tcpip.h>
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")
#pragma comment(lib, "crypt32")

void die(const char *str)
{
	//fprintf(stderr, "%s: %s\n", str, strerror(errno));
	exit(1);
}
int create_listen(int port)
{
	WSADATA wsaData = { 0 };
	int iResult = 0;
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		wprintf(L"WSAStartup failed: %d\n", iResult);
		return 1;
	}
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");

	int s = socket(AF_INET, SOCK_STREAM, 0);
	int errr = WSAGetLastError();
	if (s < 0) {
		die("Unable to create socket");
	}
	const char enable = 1;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
		die("SO_REUSEADDR failed");
	}
	if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		die("Unable to bind to port");
	}
	if (listen(s, 1) < 0) {
		die("Unable to listen on port");
	}
	printf("Listening on port %d\n", port);
	return s;
}

void init_openssl()
{
	//SSL_load_error_strings();
	//OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
	//EVP_cleanup();
}

SSL_CTX *create_context()
{
	EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
	SSL_CTX *ctx = SSL_CTX_new(SSLv23_server_method());
	if (!ctx)
		die("Unable to create SSL context");
	SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
	return ctx;
}

void keylog_callback(const SSL *ssl, const char *line)
{
	printf("%s\n", line);
}

void configure_context(SSL_CTX *ctx)
{

	if (!SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM))
		die("Unable to load server.crt");
	if (!SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM))
		die("Unable to load server.key");
	SSL_CTX_set_keylog_callback(ctx, keylog_callback);
}

int main(int argc, char **argv)
{
	// set up ssl
	init_openssl();
	SSL_CTX *ctx = create_context();
	configure_context(ctx);

	int sock = create_listen(8400);

	// accept connection
	struct sockaddr_in addr;
	int len = sizeof(addr);
	int client = accept(sock, (struct sockaddr*)&addr, &len);

	if (client < 0) {
		ERR_print_errors_fp(stderr);
		die("Unable to accept connection");
	}
	char host[NI_MAXHOST];
	char port[NI_MAXSERV];
	getnameinfo((struct sockaddr*)&addr, sizeof(addr), host, sizeof(host),
		port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
	printf("Accepted connection from %s:%s\n", host, port);

	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, client);

	if (SSL_accept(ssl) <= 0) {
		ERR_print_errors_fp(stderr);
		die("Unable to accept TLS connection");
	}

	char rbuf[128];
	int ret = SSL_read(ssl, rbuf, sizeof(rbuf) - 1);
	if (ret <= 0) {
		ERR_print_errors_fp(stderr);
		die("Unable to read from connection");
	}
	rbuf[ret] = '\0';
	printf("Read [%s]\n", rbuf);

	const char reply[] = "pong";
	if (SSL_write(ssl, reply, strlen(reply)) <= 0) {
		ERR_print_errors_fp(stderr);
		die("Unable to write to connection");
	}
	printf("Wrote [%s]\n", reply);

	SSL_free(ssl);
	closesocket(client);

	closesocket(sock);
	SSL_CTX_free(ctx);
	cleanup_openssl();
}