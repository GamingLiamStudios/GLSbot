#include "websocket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
        u8 b[3];
        if (i + 3 > size)
        {
            // Copy remaining bytes
            int l = 0;
            int r = size - i;
            while (r--) b[l++] = data[i++];
            while (l < 3) b[l++] = 0;
        }
        else
        {
            b[0] = data[i++];
            b[1] = data[i++];
            b[2] = data[i++];
        }

        base64[j++] = base64_chars[b[0] >> 2];
        base64[j++] = base64_chars[((b[0] & 0b00000011) << 4) | (b[1] >> 4)];
        if (b[1] != 0)
            base64[j++] = base64_chars[((b[1] & 0b00001111) << 2) | (b[2] >> 6)];
        else
            base64[j++] = base64_pad;
        if (b[2] != 0)
            base64[j++] = base64_chars[b[2] & 0b00111111];
        else
            base64[j++] = base64_pad;
    }

    base64[base64_size] = '\0';

    return base64;
}

int websocket_connect(struct websocket *ws, const char *url)
{
    char *tokens_main = malloc(strlen(url) + 1);
    strcpy(tokens_main, url);
    char *tokens = tokens_main;

    struct websocket websocket;
    websocket.is_connected = false;

    if (url == NULL)
    {
        printf("ERROR: Invalid host\n");
        return -1;
    }
    if (ws == NULL)
    {
        printf("ERROR: Invalid websocket\n");
        return -1;
    }

    // Parse URL
    // URL format: ws(s)://host[:port]/path?query

    char *host, *port, *path;
    char *ws_type = strtok(tokens, "//");
    tokens        = strtok(NULL, "//");
    while ((port = strtok(NULL, "//")) != NULL) *(port - 1) = '/';    // uhhhhhh

    // Parse path
    // 0 = no, 1 = /, 2 = ?
    int is_path = strchr(tokens, '/') != NULL ? 1 : (strchr(tokens, '?') != NULL ? 2 : 0);
    switch (is_path)
    {
    case 0: path = "/"; break;
    case 1:
    {
        tokens    = strtok(tokens, "/");
        char *tok = strtok(NULL, "/");
        path      = malloc(strlen(tok) + 2);
        strcpy(path, "/");
        strcat(path, tok);

        tok = NULL;
        while ((tok = strtok(NULL, "/")) != NULL)
        {
            // TODO: Handle failure of realloc
            path = realloc(path, strlen(path) + strlen(tok) + 2);    // '/' + \0
            strcat(path, "/");
            strcat(path, tok);
        }
        break;
    }
    case 2:
    {
        tokens    = strtok(tokens, "?");
        char *tok = strtok(NULL, "?");
        path      = malloc(strlen(tok) + 3);    // '/?' + \0
        strcpy(path, "/?");
        strcat(path, tok);

        tok = NULL;
        while ((tok = strtok(NULL, "?")) != NULL)
        {
            // TODO: Handle failure of realloc
            path = realloc(path, strlen(path) + strlen(tok) + 2);    // '?' + \0
            strcat(path, "?");
            strcat(path, tok);
        }
        break;
    }
    }

    // Parse port
    bool is_ssl = strcmp(ws_type, "wss:") == 0;
    port        = strcmp(ws_type, "ws:") == 0 ? "80" : (is_ssl ? "443" : NULL);
    if (port == NULL)
    {
        printf("ERROR: Invalid URL\n");
        return -1;
    }

    bool is_port = strchr(tokens, ':') != NULL;
    if (is_port)
    {
        host = strtok(tokens, ":");
        port = strtok(NULL, ":");
    }
    else
        host = tokens;

    // Connect to server
    printf("Host: %s\n", host);
    printf("Port: %s\n", port);
    printf("Path: %s\n", path);
    printf("is_ssl: %d\n\n", is_ssl);

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
    free(key_b64);
    if (strcmp(path, "/") != 0) free(path);

    printf("Request:\n%s", request);

    // Connect to server
    int porti  = atoi(port);
    ws->socket = socket_connect(host, porti, is_ssl);
    if (ws->socket.sock == NULL)
    {
        printf("ERROR: Failed to connect to server\n");
        return -1;
    }

    free(tokens_main);

    // Send handshake request
    socket_send(&ws->socket, request, req_size);
    free(request);

    // Receive handshake response
    char *response = malloc(1024);
    int   res_size = socket_recv(&ws->socket, response, 1024);

    printf("Response:\n%s\n", response);

    // TODO: Parse response D:

    free(response);

    return 0;
}