# securehttpparser

## Abstract

I propose the method of which making Lex Rules from ABNF（Augmented Backus–Naur Form).

I confirmed a prototype library including Lex Rules making from ABNF parses HTTP header correctly.

'securehttpparser,' written in Lex and C, is the prototype library including Lex Rules to parses HTTP/1.1 header generated from ABNF on RFCs related to HTTP specification.

I prepared a simple application for evaluation to get Filed Name and Filed Value in HTTP header with 'securehttpparser.'

## Use 'securehttpparser'

Include the *http_parser.h* header and call the APIs included in it from your source code.

```c
#include http_parser.h
```

You can also find the API documents written in Doxygen's JavaDoc format on the *http_parser.h* header.

## Evaluate 'securehttpparser'

You can build and run the simple application to evaluate 'securehttpparser.'

Build the simple application:

```bash
make -f Makefile.gmk all
```

Run the simple application:

```bash
./http11_parser
```

The simple application prints the following text on the terminal twice.

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

I confirmed the below tools and versions, but not limited.

- clang version 12.0.5
- flex 2.5.35
- GNU Make 3.81
