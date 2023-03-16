#ifndef HTTP_H
#define HTTP_H

#include <stdint.h>

#define XHTTP_DOC_DIR               "../htdocs"

int http_server_open(uint16_t port);
void http_server_run(void);

#endif
