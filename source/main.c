#include <stdio.h>
#include "util/types.h"

#include "websocket/websocket.h"

#include <openssl/ssl.h>

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
    websocket_connect(&ws, echo_server);

    return 0;
}