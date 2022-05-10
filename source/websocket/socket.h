#pragma once

#include "util/types.h"

// TODO: Add support for OS other than Linux
#ifdef __linux__
typedef int socket_t;
#else
#error "Unsupported OS"
#endif

struct socket
{
    bool  is_ssl;
    void *sock;
};

struct socket socket_connect(const char *host, int port, bool is_ssl);
void          socket_close(struct socket socket);

int socket_send(struct socket *socket, const char *data, int size);
int socket_recv(
  struct socket *socket,
  char          *data,
  int            size);    // Error if ret < 0, else bytes received
