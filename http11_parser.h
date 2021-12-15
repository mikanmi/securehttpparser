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
#if !defined(HTTP11_PARSER_H_)
#define HTTP11_PARSER_H_

#if defined(__cplusplus)
extern "C" {
#endif /* __cplusplus */

/**
 * If the parser will find field line, it calls this function.
 * @param name The field name.
 * @param name_length The size of name.
 * @param value The field value.
 * @param value_length The size of value.
 */
typedef void (*NOTIFY_FIELDLINE)(const char * name, int name_length, const char * value, int value_length);

/**
 * @brief parse http header.
 * @param http_header The bytes array of raw http_heder. Needed to add two 0 bytes to tail.
 * @param length The size of http_header which includes last two 0 bytes.
 * @param notify Calls the function by the parser, if field line found.
 *               The parameters, name and value, take positions within http_header area.
 * @return 1 if succeeded, 0 if parse error, otherwise -1 if general errror.
 *
 * This function accepts only rewritable bytes array regardless of function signature.
 * you can use field line after parsing one.
 * If there is no enough memory, the parser may call exit() or return -1.
 */
int parse_http11header(const void *http_header, int length, NOTIFY_FIELDLINE notify);

#if defined(__cplusplus)
}
#endif /* __cplusplus */
#endif /* HTTP11_PARSER_H_ */
