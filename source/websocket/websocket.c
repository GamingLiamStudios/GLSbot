#include "websocket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <math.h>

#include <openssl/sha.h>
#include <arpa/inet.h>

#define WS_FRAGMENT_SIZE 4096

struct wsf_header
{
    u8 opcode : 4;
    u8 rsv : 3;
    u8 fin : 1;
    u8 payload_len : 7;
    u8 mask : 1;
};

char *base64_encode(unsigned char *data, int size)
{
    const char *base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const char  base64_pad   = '=';

    int base64_size = (size + 2) / 3 * 4;

    char *base64 = malloc(base64_size + 1);
    if (base64 == NULL) return NULL;

    int i = 0;
    int j = 0;

    while (i < size)
    {
        u8 b[3] = { 0 };

        int l = 0;
        if (i + 3 > size)
        {
            int r = size - i;
            while (r--) b[l++] = data[i++];
        }
        else
        {
            b[l++] = data[i++];
            b[l++] = data[i++];
            b[l++] = data[i++];
        }

        base64[j++] = base64_chars[b[0] >> 2];
        base64[j++] = base64_chars[((b[0] & 0x03) << 4) | (b[1] >> 4)];
        base64[j++] = (l > 1) ? base64_chars[((b[1] & 0x0F) << 2) | (b[2] >> 6)] : base64_pad;
        base64[j++] = (l > 2) ? base64_chars[b[2] & 0x3F] : base64_pad;
    }

    base64[base64_size] = '\0';

    return base64;
}

int websocket_connect(struct websocket *ws, const char *aurl)
{
    ws->is_connected = false;

    if (aurl == NULL)
    {
        printf("ERROR: Invalid host\n");
        return -1;
    }
    if (ws == NULL)
    {
        printf("ERROR: Invalid websocket\n");
        return -1;
    }

    char *url = malloc(strlen(aurl) + 1);
    if (url == NULL)
    {
        printf("ERROR: Out of memory\n");
        return -1;
    }
    strcpy(url, aurl);
    url[strlen(aurl)] = '\0';

    // Parse URL
    // URL format: ws[s]://host[:port]/path?query

    // Parse port
    bool  is_ssl = strncmp(url, "wss://", 6) == 0;
    char *port   = strncmp(url, "ws://", 5) == 0 ? "80" : (is_ssl ? "443" : NULL);
    if (port == NULL)
    {
        printf("ERROR: Invalid URL\n");
        return -1;
    }

    // Parse path
    char *tokens = strchr(url, '/') + 2;
    char *path   = strchr(tokens, '/') != NULL
        ? (strchr(tokens, '?') != NULL && strchr(tokens, '/') > strchr(tokens, '?')
             ? strchr(tokens, '?')
             : strchr(tokens, '/'))
        : (strchr(tokens, '?') != NULL ? strchr(tokens, '?') : "/");

    // Parse host
    char *host = malloc(strlen(tokens) - strlen(path) + (strlen(path) == 1) + 1);
    strncpy(host, tokens, strlen(tokens) - strlen(path) + (strlen(path) == 1));
    bool is_port = strchr(tokens, ':') != NULL;
    if (is_port)
    {
        port        = strchr(host, ':') + 1;
        *(port - 1) = '\0';
    }

    // Build handshake request
    const char *fmt =
      "GET %s HTTP/1.1\r\n"
      "Host: %s%s\r\n"
      "Upgrade: websocket\r\n"
      "Connection: Upgrade\r\n"
      "Sec-WebSocket-Key: %s\r\n"
      "Sec-WebSocket-Version: 13\r\n"
      "\r\n";

    // Generate Sec-WebSocket-Key
    u8 *key = malloc(16);
    for (int i = 0; i < 16; i++) key[i] = rand() % 256;

    // Base64 encode Sec-WebSocket-Key
    char *key_b64 = base64_encode(key, 16);

    int   req_size = snprintf(NULL, 0, fmt, path, host, is_port ? port : "", key_b64);
    char *request  = malloc(req_size + 1);
    snprintf(request, req_size + 1, fmt, path, host, is_port ? port : "", key_b64);

    free(key);
    // free(key_b64);

    // Connect to server
    int porti  = atoi(port);
    ws->socket = socket_connect(host, porti, is_ssl);
    if (ws->socket.sock == NULL)
    {
        printf("ERROR: Failed to connect to server\n");
        free(key_b64);
        return -1;
    }

    free(host);

    // Send handshake request
    if (socket_send(&ws->socket, request, req_size) < 0)
    {
        printf("ERROR: Failed to send handshake request\n");
        free(request);
        free(key_b64);
        socket_close(ws->socket);
        return -1;
    }
    free(request);

    // While we wait for that, let's make the SHA-1 hash for verification
    const char *vstr     = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    int         vstr_len = strlen(key_b64) + strlen(vstr);
    char       *vstr_cat = malloc(vstr_len + 1);
    strcpy(vstr_cat, key_b64);
    strcat(vstr_cat, vstr);
    free(key_b64);

    u8 *vstr_sha1 = malloc(SHA_DIGEST_LENGTH);
    SHA1((const u8 *) vstr_cat, vstr_len, vstr_sha1);
    free(vstr_cat);

    char *sha1_b64 = base64_encode(vstr_sha1, SHA_DIGEST_LENGTH);
    free(vstr_sha1);

    // Receive handshake response
    char *response = malloc(1024);
    memset(response, 0, 1024);
    int res_size = socket_recv(&ws->socket, response, 1024);
    if (res_size < 0)
    {
        printf("ERROR: Failed to receive handshake response\n");
        free(response);
        free(sha1_b64);
        socket_close(ws->socket);
        return -1;
    }

    // Verify we got a known response
    char *line = strtok(response, "\r\n");
    if (strcmp(line, "HTTP/1.1 101 Switching Protocols") != 0)
    {
        printf("ERROR: Unknown response\n%s\n", line);
        free(response);
        free(sha1_b64);
        socket_close(ws->socket);
        return -1;
    }

    // Parse response headers
    int found = 3;
    while ((line = strtok(NULL, "\r\n")) != NULL)
    {
        char *val = strchr(line, ':') + 2;
        if (val == NULL)
        {
            printf("ERROR: Malformed response\n");
            free(response);
            free(sha1_b64);
            socket_close(ws->socket);
            return -1;
        }
        char *key  = line;
        *(val - 2) = '\0';

        if (strcasecmp(key, "Upgrade") == 0)
        {
            if (strcasecmp(val, "websocket") != 0)
            {
                printf("ERROR: Invalid Upgrade\n");
                free(response);
                free(sha1_b64);
                socket_close(ws->socket);
                return -1;
            }
            found--;
        }

        if (strcasecmp(key, "Connection") == 0)
        {
            if (strcasecmp(val, "Upgrade") != 0)
            {
                printf("ERROR: Invalid Connection\n");
                free(response);
                free(sha1_b64);
                socket_close(ws->socket);
                return -1;
            }
            found--;
        }

        if (strcasecmp(key, "Sec-WebSocket-Accept") == 0)
        {
            if (strcmp(val, sha1_b64) != 0)
            {
                printf("ERROR: Invalid Sec-WebSocket-Accept\n");
                free(response);
                free(sha1_b64);
                socket_close(ws->socket);
                return -1;
            }
            found--;
        }

        if (
          strcasecmp(key, "Sec-WebSocket-Extensions") == 0 ||
          strcasecmp(key, "Sec-WebSocket-Protocol") == 0)
        {
            printf("ERROR: Invalid header %s\n", key);
            free(response);
            free(sha1_b64);
            socket_close(ws->socket);
            return -1;
        }
    }

    if (found != 0)
    {
        printf("ERROR: Invalid response\n");
        free(response);
        free(sha1_b64);
        socket_close(ws->socket);
        return -1;
    }

    free(response);

    ws->is_connected = true;
    printf("Successfully connected to server\n");

    return 0;
}

void websocket_close(struct websocket *ws)
{
    if (!ws->is_connected) return;
    websocket_send(ws, WS_OPCODE_CLOSE, "", 0);
    ws->is_connected = false;
    socket_close(ws->socket);
}

int websocket_send(struct websocket *ws, enum ws_opcode type, const char *data, u64 size)
{
    if (!ws->is_connected) return -1;

    u8 payload[WS_FRAGMENT_SIZE + sizeof(struct wsf_header) + sizeof(u16) + sizeof(u32)];

    int fragments = ceil(size / (double) (WS_FRAGMENT_SIZE));
    for (int f = 0; f < fragments; f++)
    {
        struct wsf_header *header = (struct wsf_header *) payload;
        header->fin               = (f == fragments - 1);
        header->rsv               = 0;
        header->opcode            = (f == 0) ? type : WS_OPCODE_CONTINUATION;
        header->mask              = 1;

        u64 rem             = size - (f * WS_FRAGMENT_SIZE);
        u16 payload_len     = (rem > WS_FRAGMENT_SIZE) ? WS_FRAGMENT_SIZE : rem;
        header->payload_len = payload_len;
        if (payload_len > 125)
        {
            header->payload_len = 126;
            u8 *payload_lenb    = (u8 *) (payload + sizeof(struct wsf_header));
            payload_lenb[0]     = (payload_len >> 8) & 0xFF;
            payload_lenb[1]     = payload_len & 0xFF;
        }

        u8 *mask_key =
          (u8 *) (payload + sizeof(struct wsf_header) + (payload_len > 125 ? sizeof(u16) : 0));
        mask_key[0] = rand() % 256;
        mask_key[1] = rand() % 256;
        mask_key[2] = rand() % 256;
        mask_key[3] = rand() % 256;

        u8 *payload_data =
          (u8
             *) (payload + sizeof(struct wsf_header) + (payload_len > 125 ? sizeof(u16) : 0) + sizeof(u32));
        memcpy(payload_data, data + f * WS_FRAGMENT_SIZE, payload_len);

        for (int i = 0; i < payload_len; i++) payload_data[i] ^= mask_key[i % 4];

        if (
          socket_send(
            &ws->socket,
            (const char *) payload,
            sizeof(struct wsf_header) + (payload_len > 125 ? sizeof(u16) : 0) + sizeof(u32) +
              payload_len) < 0)
        {
            printf("ERROR: Failed to send data\n");
            return -1;
        }
    }

    return 0;
}

int websocket_recv(struct websocket *ws, char *data, u64 *size)
{
    if (!ws->is_connected) return -1;

    bool buffer = data != NULL;
    bool frag   = false;
    u64  len    = 0;

    enum ws_opcode type = WS_OPCODE_CONTINUATION;

    struct wsf_header frame;
    while (true)
    {
        int res = socket_recv(&ws->socket, (char *) &frame, sizeof(struct wsf_header));
        if (res < 0) return -1;

        if (frame.rsv)
        {
            printf("ERROR: RSV bits not implemented\n");
            return -1;
        }

        // Check for invalid opcode
        switch (frame.opcode)
        {
        case WS_OPCODE_CONTINUATION:
        case WS_OPCODE_BINARY:
        case WS_OPCODE_TEXT:
        case WS_OPCODE_PING:
        case WS_OPCODE_PONG:
        case WS_OPCODE_CLOSE: break;
        default: printf("ERROR: Invalid opcode\n"); return -1;
        }

        // Verify payload
        bool control = true;
        switch (frame.opcode)
        {
        case WS_OPCODE_CONTINUATION:
            if (!frag)
            {
                printf("ERROR: Fragmented frame without a start\n");
                return -1;
            }
        case WS_OPCODE_BINARY:
        case WS_OPCODE_TEXT: control = false; break;
        default:
            if (!frame.fin)
            {
                printf("ERROR: Invalid fragment\n");
                return -1;
            }
            if (frame.payload_len > 125)
            {
                printf("ERROR: Invalid payload length\n");
                return -1;
            }
        }

        if (!control && !frag) type = frame.opcode;

        // Grab Extended Payload Length if necessary
        u64 data_size = frame.payload_len;
        switch (data_size)
        {
        case 126:    // 16 bit Extended length
        {
            u8 data_size_16[2];
            res = socket_recv(&ws->socket, (char *) &data_size_16, sizeof(u16));
            if (res < 0)
            {
                printf("ERROR: Unable to read frame\n");
                return -1;
            }

            data_size = data_size_16[0] << 8 | data_size_16[1];
            break;
        }
        case 127:    // 64 bit Extended length
        {
            u64 data_size_64;
            res = socket_recv(&ws->socket, (char *) &data_size_64, sizeof(u64));
            if (res < 0)
            {
                printf("ERROR: Unable to read frame\n");
                return -1;
            }

            // Check for little-endian
            u16 test = 1;
            if (*(u8 *) &test == 1)
            {
                // Cross platform byteswap
                data_size_64 = ((data_size_64 & 0x00000000000000FFu) << 56u) |
                  ((data_size_64 & 0x000000000000FF00u) << 40u) |
                  ((data_size_64 & 0x0000000000FF0000u) << 24u) |
                  ((data_size_64 & 0x00000000FF000000u) << 8u) |
                  ((data_size_64 & 0x000000FF00000000u) >> 8u) |
                  ((data_size_64 & 0x0000FF0000000000u) >> 24u) |
                  ((data_size_64 & 0x00FF000000000000u) >> 40u) |
                  ((data_size_64 & 0xFF00000000000000u) >> 56u);
            }

            data_size = data_size_64;
            break;
        }
        default: break;
        }

        // Grab masking-key if present
        u8 mask_key[4];
        if (frame.mask)
        {
            res = socket_recv(&ws->socket, (char *) &mask_key, sizeof(mask_key));
            if (res < 0)
            {
                printf("ERROR: Unable to read frame\n");
                return -1;
            }
        }

        // Read payload
        if (buffer)
        {
            if (len + data_size > *size)
            {
                printf("ERROR: Payload too large\n");
                return -1;
            }

            res = socket_recv(&ws->socket, data + len, data_size);
        }
        else
        {
            if (len == 0)
                data = malloc(data_size);
            else
            {
                char *tmp = realloc(data, len + data_size);
                if (tmp == NULL)
                {
                    printf("ERROR: Unable to allocate memory\n");
                    return -1;
                }
                data = tmp;
            }
            res = socket_recv(&ws->socket, data + len, data_size);
        }

        // Unmask data
        if (frame.mask)
            for (int i = 0; i < data_size; i++) data[len + i] ^= mask_key[i & 0b11];

        len += data_size;

        // Handle control frames
        switch (frame.opcode)
        {
        case WS_OPCODE_CLOSE:
            printf("Server closed connection\n");
            ws->is_connected = false;
            socket_close(ws->socket);
            return WS_OPCODE_CLOSE;
        case WS_OPCODE_PING: websocket_send(ws, WS_OPCODE_PONG, data, data_size);
        default: break;
        }

        // Check for continuation
        if (frame.fin && !control) break;
    }

    *size = len;

    return type;
}