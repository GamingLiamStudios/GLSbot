#include "websocket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <openssl/sha.h>

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
    // URL format: ws[s]://host[:port]/path?query

    char *host, *port, *path;
    char *ws_type = strtok(tokens, "/");
    tokens        = strtok(NULL, "/");
    while ((port = strtok(NULL, "/")) != NULL) *(port - 1) = '/';    // uhhhhhh

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

    // Parse host
    bool is_port = strchr(tokens, ':') != NULL;
    if (is_port)
    {
        host = strtok(tokens, ":");
        port = strtok(NULL, ":");
    }
    else
        host = tokens;

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
    if (strcmp(path, "/") != 0) free(path);

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

    // While we wait for that, let's make the SHA-1 hash for verification
    const char *vstr     = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    int         vstr_len = strlen(key_b64) + strlen(vstr);
    char       *vstr_cat = malloc(vstr_len + 1);
    strcpy(vstr_cat, key_b64);
    strcat(vstr_cat, vstr);

    u8 *vstr_sha1 = malloc(SHA_DIGEST_LENGTH);
    SHA1((const u8 *) vstr_cat, vstr_len, vstr_sha1);
    free(vstr_cat);

    char *sha1_b64 = base64_encode(vstr_sha1, SHA_DIGEST_LENGTH);
    free(vstr_sha1);

    // Receive handshake response
    char *response = malloc(1024);
    memset(response, 0, 1024);
    int res_size = socket_recv(&ws->socket, response, 1024);

    // Verify we got a known response
    char *line = strtok(response, "\r\n");
    if (strcmp(line, "HTTP/1.1 101 Switching Protocols") != 0)
    {
        printf("ERROR: Unknown response\n%s\n", line);
        free(response);
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
            if (sha1_b64) free(sha1_b64);
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
                if (sha1_b64) free(sha1_b64);
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
                if (sha1_b64) free(sha1_b64);
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
                if (sha1_b64) free(sha1_b64);
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
            if (sha1_b64) free(sha1_b64);
            return -1;
        }
    }

    if (found != 0)
    {
        printf("ERROR: Invalid response\n");
        free(response);
        if (sha1_b64) free(sha1_b64);
        return -1;
    }

    free(response);

    // Suprise Pikachu Face
    printf("Oh shit\n");

    return 0;
}