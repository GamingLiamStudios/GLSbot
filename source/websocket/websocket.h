#pragma once

#include "socket.h"
#include "util/types.h"

enum ws_opcode
{
    WS_OPCODE_CONTINUATION = 0x0,
    WS_OPCODE_TEXT         = 0x1,
    WS_OPCODE_BINARY       = 0x2,
    WS_OPCODE_CLOSE        = 0x8,
    WS_OPCODE_PING         = 0x9,
    WS_OPCODE_PONG         = 0xA
};

struct websocket
{
    struct socket socket;
    bool          is_connected;
};

int  websocket_connect(struct websocket *ws, const char *host);
void websocket_close(struct websocket *ws);

int websocket_send(struct websocket *ws, enum ws_opcode type, const char *data, u64 size);
// Will return -1 on error and enum ws_opcode on success
int websocket_recv(struct websocket *ws, char *data, u64 *size);
