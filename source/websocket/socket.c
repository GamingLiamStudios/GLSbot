#include "socket.h"

#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>

#include <string.h>

#include <openssl/ssl.h>

struct ssl_context
{
    SSL_CTX *ctx;
    BIO     *bio;
};

struct socket socket_connect(const char *host, int port, bool is_ssl)
{
    struct socket      sock;
    struct sockaddr_in serv_addr;
    struct hostent    *server;
    int                sockfd;

    sock.is_ssl = is_ssl;
    sock.sock   = NULL;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        printf("socket: %s\n", strerror(errno));
        return sock;
    }

    server = gethostbyname(host);
    if (server == NULL)
    {
        fprintf(stderr, "ERROR, no such host\n");
        exit(0);
    }

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *) server->h_addr, (char *) &serv_addr.sin_addr.s_addr, server->h_length);
    serv_addr.sin_port = htons(port);

    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) != 0)
    {
        printf("connect: %s\n", strerror(errno));

        close(sockfd);
        return sock;
    }

    if (!is_ssl)
    {
        sock.sock          = malloc(sizeof(int));
        *(int *) sock.sock = sockfd;

        return sock;
    }

    // Create TLS context
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) return sock;

    // Create SSL object
    BIO *bio = BIO_new_ssl_connect(ctx);
    if (bio == NULL) return sock;

    // Set hostname
    char *ports = malloc(strlen(host) + 6 + 2);
    strcpy(ports, host);
    strcat(ports, ":");
    char port_str[6];
    snprintf(ports + strlen(host) + 1, 7, "%d", port);
    BIO_set_conn_hostname(bio, ports);
    SSL *ssl;
    BIO_get_ssl(bio, &ssl);
    SSL_set_tlsext_host_name(ssl, host);
    free(ports);

    // Connect to server
    if (BIO_do_connect(bio) <= 0)
    {
        printf("BIO_do_connect: %s\n", strerror(errno));
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return sock;
    }
    if (BIO_do_handshake(bio) <= 0)
    {
        printf("BIO_do_handshake: %s\n", strerror(errno));
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
        return sock;
    }

    struct ssl_context *ssl_c = malloc(sizeof(struct ssl_context));
    ssl_c->ctx                = ctx;
    ssl_c->bio                = bio;

    sock.sock = ssl_c;

    return sock;
}

void socket_close(struct socket socket)
{
    if (socket.is_ssl)
    {
        struct ssl_context *ssl = (struct ssl_context *) socket.sock;
        BIO_free_all(ssl->bio);
        SSL_CTX_free(ssl->ctx);
        free(ssl);

        socket.sock = NULL;
        return;
    }

    shutdown(*(int *) socket.sock, SHUT_RDWR);
    free(socket.sock);

    socket.sock = NULL;
}

int socket_send(struct socket *socket, const char *data, int size)
{
    if (!socket->is_ssl)
    {
        int ret = send(*(int *) socket->sock, data, size, 0);
        if (ret == -1)
        {
            printf("send: %s\n", strerror(errno));
            return -1;
        }
        return ret;
    }

    struct ssl_context *ssl = (struct ssl_context *) socket->sock;
    int                 ret = BIO_write(ssl->bio, data, size);

    if (ret != size)
    {
        ret = socket_send(socket, data + ret, size - ret);
        if (ret < 0) return -1;
    }
    if (ret <= 0)
    {
        if (ret == -2)
        {
            printf("BIO_write is not implemented\n");
            return -1;
        }

        if (BIO_should_retry(ssl->bio)) return socket_send(socket, data, size);

        // TODO: Do this better
        printf("BIO_write: %s\n", BIO_get_retry_reason(ssl->bio));
        return -1;
    }

    return ret;
}

int socket_recv(struct socket *socket, char *data, int size)
{
    if (!socket->is_ssl)
    {
        int ret = recv(*(int *) socket->sock, data, size, 0);
        if (ret == -1)
        {
            printf("recv: %s\n", strerror(errno));
            return -1;
        }
        return ret;
    }

    struct ssl_context *ssl = (struct ssl_context *) socket->sock;
    int                 ret = BIO_read(ssl->bio, data, size);

    if (ret < 0)
    {
        if (ret == -2)
        {
            printf("BIO_read is not implemented\n");
            return -1;
        }

        if (BIO_should_retry(ssl->bio)) return socket_recv(socket, data, size);

        // TODO: Do this better
        printf("BIO_read: %s\n", BIO_get_retry_reason(ssl->bio));
        return -1;
    }

    return ret
}