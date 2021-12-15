# securehttpparser

## Abstract

'securehttpparser' is a parser library of HTTP/1.1 Header written on Lex and C.
An application get Filed Name and Value contained in HTTP/1.1 Header with 'securehttpparser'.

## How to use

Include the below header file.

```bash
#include http_parser.h
```

The APIs, function signatures and specifications as Doxygen's javadoc format, are written into the header.

## Evaluation

You get the simple application to evaluate the http11_parser

Build the simple application:

```bash
make -f Makefile.gmk all
```

Run the simple application:

```bash
./http11_parser
```

The simple application prints the following twice.

```bash
name    10: User-Agent: curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3
value   52: curl/7.16.3 libcurl/7.16.3 OpenSSL/0.9.7l zlib/1.2.3
name     4: Host: www.example.com
value   15: www.example.com
name    15: Accept-Language: en, mi
value    6: en, mi
result: 1
cmp: 0
```

## Environment  

The development environment.

Needed for building the parser.

- gcc
- flex

For building the simple application.

- gmake
