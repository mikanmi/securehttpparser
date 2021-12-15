/*
BSD 2-Clause License

Copyright (c) 2020, 2021, Patineboot
All rights reserved.
*/
#include <stdio.h>
#include <string.h>
#include "http11_parser.h"

#define STRING_NO_NIL(name, message) char name[sizeof(message)-1] = {message}

STRING_NO_NIL(http_header, 
    "GET /hello.txt HTTP/1.1\x0d\x0a"
    "User-Agent: curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3\x0d\x0a"
    "Host: www.example.com\x0d\x0a"
    "Accept-Language: en, mi\x0d\x0a"
    "\x0d\x0a"
    "\0\0"
);

STRING_NO_NIL(http_message, 
    "GET /hello.txt HTTP/1.1\x0d\x0a"
    "User-Agent: curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3\x0d\x0a"
    "Host: www.example.com\x0d\x0a"
    "Accept-Language: en, mi\x0d\x0a"
    "\x0d\x0a"
    "body\x00\xFF"
    "\0\0"
);


static void handler(const char *name, int name_length, const char *value, int value_length)
{
    printf("name  %4d: %s\n", name_length, name);
    printf("value %4d: %s\n", value_length, value);
}

void evaluate(char *message, int lenght)
{
    char verify[lenght];
    memcpy(verify, message, lenght);

    int result = parse_http11header(&message[0], lenght, handler);
    printf("result: %d\n", result);

    for(int i = 0; i < lenght; i++) {
        if (verify[i] != message[i]) {
            printf("unmatch index: %d\n", i);
        }
    }
    printf("cmp: %d\n", memcmp(verify, message, lenght));
}

int main(void)
{
    evaluate(http_header, sizeof(http_header));
    evaluate(http_message, sizeof(http_message));
    return 1;
}