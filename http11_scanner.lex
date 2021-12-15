/*
BSD 2-Clause License

Copyright (c) 2020, 2021, Patineboot
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

%{
#define FIELD_NAME  (1)
#define FIELD_VALUE (2)
#define SCAN_ERROR (3)
%}
%option reentrant
%option noinput
%option nounput
%option noyy_push_state
%option noyy_pop_state
%option noyy_top_state
%option noyy_scan_bytes
%option noyy_scan_string

/* ----- RFC 5234 Augmented BNF for Syntax Specifications: ABNF */

ALPHA [A-Za-z]
DIGIT [0-9]
HEXDIG {DIGIT}|[A-F]
VCHAR [\x21-\x7E]
OCTET [\x00-\xFF]

HTAB \x09
SP \x20
CR \x0D
LF \x0A
CRLF {CR}{LF}

/* ----- RFC 3986: Uniform Resource Identifier (URI): Generic Syntax */

unreserved {ALPHA}|{DIGIT}|[\-\.\_\~]
pct-encoded \%{HEXDIG}{HEXDIG}
sub-delims [\!\$\&\'\(\)\*\+\,\;\=]
pchar {unreserved}|{pct-encoded}|{sub-delims}|[\:\@]
reg-name ({unreserved}|{pct-encoded}|{sub-delims})*

dec-octet {DIGIT}|[1-9]{DIGIT}|1{DIGIT}{2}|2[0-4]{DIGIT}|25[0-5]
IPv4address {dec-octet}\.{dec-octet}\.{dec-octet}\.{dec-octet}
IPvFuture v{HEXDIG}+\.({unreserved}|{sub-delims}|\:)+
h16 {HEXDIG}{1,4}
ls32 ({h16}\:{h16})|{IPv4address}
IPv6address (({h16}\:){6}{ls32})|(\:\:({h16}\:){5}{ls32})|({h16}?\:\:({h16}\:){4}{ls32})|((({h16}\:){0,1}{h16})?\:\:({h16}\:){3}{ls32})|((({h16}\:){0,2}{h16})?\:\:({h16}\:){2}{ls32})|((({h16}\:){0,3}{h16})?\:\:({h16}\:){1}{ls32})|((({h16}\:){0,4}{h16})?\:\:{ls32})|((({h16}\:){0,5}{h16})?\:\:{h16})|((({h16}\:){0,6}{h16})?\:\:)
IP-literal \[({IPv6address}|{IPvFuture})\]

userinfo  ({unreserved}|{pct-encoded}|{sub-delims}|\:)*
host {IP-literal}|{IPv4address}|{reg-name}
port {DIGIT}*
authority ({userinfo}\@)*{host}(\:{port})*

segment {pchar}*
segment-nz {pchar}+
path-abempty (\/{segment})*
path-absolute \/({segment-nz}(\/{segment})*)*
path-rootless {segment-nz}(\/{segment})*
/* empty 0<pchars> */
/* path-empty {pchars}{0} */

scheme {ALPHA}({ALPHA}|{DIGIT}|[\+\-\.])*
/* hier-part (\/\/{authority}{path-abempty})|{path-absolute}|{path-rootless}|{path-empty} */
hier-part ((\/\/{authority}{path-abempty})|{path-absolute}|{path-rootless})?
query ({pchar}|[\/\?])*

absolute-URI {scheme}\:{hier-part}(\?{query})?

/* ----- HTTP Semantics */

OWS ({SP}|{HTAB})*

tchar [\!\#\$\%\&\'\*\+\-\.\^\_\`\|\~]|{DIGIT}|{ALPHA}
token {tchar}+

obs-text [\x80-\xFF]

absolute-path (\/{segment})+

field-vchar {VCHAR}|{obs-text}
field-content {field-vchar}(({SP}|{HTAB}|{field-vchar})+{field-vchar})?

field-name {token}
field-value {field-content}*

/* ----- HTTP/1.1 Messaging */

method {token}

origin-form {absolute-path}(\?{query})?
absolute-form {absolute-URI}
authority-form {authority}
asterisk-form \*
request-target {origin-form}|{absolute-form}|{authority-form}|{asterisk-form}

HTTP-name HTTP
HTTP-version {HTTP-name}\/{DIGIT}\.{DIGIT}

status-code {DIGIT}{3}
reason-phrase  ({HTAB}|{SP}|{VCHAR}|{obs-text})+

request-line {method}{SP}{request-target}{SP}{HTTP-version}
status-line {HTTP-version}{SP}{status-code}{SP}{reason-phrase}?

start-line {request-line}|{status-line}
field-line {field-name}\:{OWS}{field-value}{OWS}
message-body {OCTET}*

HTTP-message {start-line}{CRLF}({field-line}{CRLF})*{CRLF}{message-body}?

%x finding_start_line
%x finding_field_name
%x finding_field_delimiter
%x finding_field_value
%x finding_field_following
/* TODO: scanning body */
%x finding_message_body

%%
 /* Rules from below commented defines */
 /* HTTP-message {start-line}{CRLF}({field-line}{CRLF})*{CRLF}{message-body}? */
 /* field-line {field-name}\:{OWS}{field-value}{OWS} */

<INITIAL,finding_start_line>{start-line}{CRLF} {
    BEGIN(finding_field_name);
}
<finding_field_name>{field-name} {
    BEGIN(finding_field_delimiter);
    return FIELD_NAME;
}
<finding_field_delimiter>\:{OWS} {
    BEGIN(finding_field_value);
}
<finding_field_value>{field-value} {
    BEGIN(finding_field_following);
    return FIELD_VALUE;
}
<finding_field_following>{OWS}{CRLF} {
    BEGIN(finding_field_name);
}
<finding_field_name>{CRLF} {
    BEGIN(finding_message_body);
}
<finding_message_body>{message-body} {
    /* if need multi HTTP-message */
    BEGIN(finding_start_line);
}
<*>{OCTET} {
    /* broken messsage */
    return SCAN_ERROR;
}

%%

#include "http11_parser.h"

int parse_http11header(const void *http_header, int length, NOTIFY_FIELDLINE notify)
{
    yyscan_t scanner;
    if (0 != yylex_init(&scanner)) {
        return -1;
    }

    /* hope that scaneer will not rewrite the message */
    void *message = (void *)http_header;
    YY_BUFFER_STATE state = yy_scan_buffer(message, length, scanner);
    if (state == 0) {
        /* not terminated with two zero */
        /* if not allocated, called exit() by the function */
        return -1;
    }

    /* parse http header */
    int result = 1;
    int token;
    /* initialize field name to singular values */
    const char* name = 0;
    int name_length = -1;
    while ((token = yylex(scanner)) > 0) {
        if (token == FIELD_NAME) {
            /* field name */
            name = yyget_text(scanner);
            name_length = yyget_leng(scanner);
        }
        else if (token == FIELD_VALUE) {
            /* notify name and value */
            /* name is no longer terminated with zero */
            notify(name, name_length, yyget_text(scanner), yyget_leng(scanner));
        }
        /* SCAN_ERROR */
        else {
            /* continue scanning to the end */
            result = 0;
        }
    }

    yy_delete_buffer(state, scanner);
    yylex_destroy(scanner);

    return result;
}
