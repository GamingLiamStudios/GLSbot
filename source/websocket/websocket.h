#pragma once

#include "socket.h"
#include "util/types.h"

struct websocket
{
    struct socket socket;
    bool          is_connected;
};

int  websocket_connect(struct websocket *ws, const char *host);
void websocket_close(struct websocket websocket);

int websocket_send(struct websocket *websocket, const char *data, int size);
int websocket_recv(struct websocket *websocket, char *data, int size);
