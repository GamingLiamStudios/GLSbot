#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "util/types.h"

#include "websocket/websocket.h"

#include <openssl/ssl.h>
#include <unistd.h>

int main(int argv, char **argc)
{
    // Initalize SSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    srand(time(NULL));

    const char *echo_server = "wss://ws.ifelse.io";
    printf("Hello World!\n");

    struct websocket ws;
    if (websocket_connect(&ws, echo_server) < 0)
    {
        printf("ERROR: Failed to connect to server\n");
        return -1;
    }

    char *message =
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    websocket_send(&ws, WS_OPCODE_TEXT, message, strlen(message));

    sleep(2);

    char *buffer = malloc(1025);
    u64   len    = 1024;
    int   opcode = websocket_recv(&ws, buffer, &len);
    if (opcode < 0)
    {
        printf("ERROR: Failed to recv message\n");
        return -1;
    }
    if (opcode == WS_OPCODE_CLOSE) return 0;

    printf("Received op %u len %lu\n", opcode, len);

    if (len > 0)
    {
        buffer[len] = '\0';
        printf("Received: %s\n", buffer);
    }

    len    = 1024;
    opcode = websocket_recv(&ws, buffer, &len);
    if (opcode < 0)
    {
        printf("ERROR: Failed to recv message\n");
        return -1;
    }
    if (opcode == WS_OPCODE_CLOSE) return 0;

    printf("Received op %u len %lu\n", opcode, len);

    if (len > 0)
    {
        buffer[len] = '\0';
        printf("Received: %s\n", buffer);
    }

    free(buffer);

    websocket_close(&ws);

    return 0;
}