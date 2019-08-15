/*
 * Copyright (C) 2012, 2013, 2014 James McLaughlin et al.  All rights reserved.
 * https://github.com/udp/json-parser
 * Copyright (C) 2019 Thad Megow et al.  All rights reserved.
 * https://github.com/tmegow/jp
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "json.h"

#ifdef _MSC_VER
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <stdint.h>
#endif

const struct _json_value json_value_none;

#define PCRE2_CODE_UNIT_WIDTH 8
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <math.h>
#include <pcre2.h>

typedef unsigned int json_uchar;
int MATCH_KEYS = 1;
int SAVE_VALUES = 1;

// thad mods
long int int_char_length (long int value)
{
    long int count = 0;
    while(value != 0)
    {
        value /= 10;
        ++count;
    }
    return count;
}

static char * prepend_str_const(char * jp, const char * pre)
{
    char * temp = (char *) realloc(jp, strlen(pre) + strlen(jp) + 1);
    if (!temp)
    {
        return 0;
    }
    jp = temp;
    void * ptr = memmove(jp + strlen(pre), jp, strlen(jp) + 1);
    assert(ptr == jp + strlen(pre));
    for (size_t i=0; i < strlen(pre); ++i)
    {
        jp[i] = pre[i];
    }
    return jp;
}

int has_whitespace (char * str)
{
    int whitespace_found = 0;
    for (size_t i=0; i < strlen(str); ++i)
    {
        switch (str[i])
        {
            case ' ':
            case '\t':
            case '\n':
            case '\r':
                whitespace_found = 1;
                break;
        }
        if (whitespace_found)
            break;
    }
    return whitespace_found;
}

int check_parent_exists (json_value * value)
{
    if (value)
    {
        if (value->parent)
        {
            return 1;
        }
        else
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }
}

int re_match(char * regex, char * value)
{

    int Found = 0;
    pcre2_code * re;
    PCRE2_SPTR pattern;
    PCRE2_SPTR subject;
    int errornumber;
    int rc;
    PCRE2_SIZE erroroffset;
    size_t subject_length;
    pcre2_match_data * match_data;

    pattern = (PCRE2_SPTR)regex;
    subject = (PCRE2_SPTR)value;
    subject_length = strlen((char *)subject);

    re = pcre2_compile(
             pattern,               /* the pattern */
             PCRE2_ZERO_TERMINATED, /* indicates pattern is zero-terminated */
             0,                     /* default options */
             &errornumber,          /* for error number */
             &erroroffset,          /* for error offset */
             NULL);                 /* use default compile context */

    if (re == NULL)
    {
        PCRE2_UCHAR buffer[256];
        pcre2_get_error_message(errornumber, buffer, sizeof(buffer));
        printf("PCRE2 compilation failed at offset %d: %s\n", (int)erroroffset,buffer);
        return 1;
    }

    match_data = pcre2_match_data_create_from_pattern(re, NULL);

    rc = pcre2_match(
             re,
             subject,              /* the subject string */
             subject_length,       /* the length of the subject */
             0,                    /* start at offset 0 in the subject */
             0,                    /* default options */
             match_data,           /* block for storing the result */
             NULL);

    if (rc < 0)
    {
        switch(rc)
        {
            case PCRE2_ERROR_NOMATCH:
                pcre2_match_data_free(match_data);
                pcre2_code_free(re);
                Found = 0;
                return Found;
            default:
                printf("Matching error %d\n", rc);
                Found = 0;
                return Found;
        }
        pcre2_match_data_free(match_data);
        pcre2_code_free(re);
        Found = 0;
        return Found;
    }
    if(rc > 0)
    {
        Found = 1;

    }
    pcre2_match_data_free(match_data);
    pcre2_code_free(re);
    return Found;
}

char * climb (json_value * val, char * current_jp, jp * found)
{
    current_jp = (char *) calloc(1, 1 * sizeof(char));
    char * char_array_tmp;
    char * char_array_tmp2;
    char ** char_ptr_array_tmp;
    while (check_parent_exists(val))
    {
        switch (val->parent->type)
        {
            case json_object:
                if (has_whitespace(val->parent->u.object.values[val->parent->u.object.length].name))
                {
                    char_array_tmp = (char *) malloc(sizeof(char) * val->parent->u.object.values[val->parent->u.object.length].name_length + 5);
                    sprintf(char_array_tmp, "[\'%s\']", val->parent->u.object.values[val->parent->u.object.length].name);
                    char_array_tmp2 = (char *) realloc(current_jp, sizeof(char) * found->jps_longest + val->parent->u.object.values[val->parent->u.object.length].name_length + 5);
                    if (!char_array_tmp2)
                    {
                        return 0;
                    }
                    current_jp = char_array_tmp2;
                    if (found->jps_longest < found->jps_longest + val->parent->u.object.values[val->parent->u.object.length].name_length + 5)
                    {
                        found->jps_longest = found->jps_longest + val->parent->u.object.values[val->parent->u.object.length].name_length + 5;
                    }
                    current_jp = prepend_str_const(current_jp, char_array_tmp);
                    free(char_array_tmp);
                    if (!current_jp)
                    {
                        puts("prepend_str_const problem\n");
                    }
                    if (found->check_keys && re_match(found->regex, val->parent->u.object.values[val->parent->u.object.length].name))
                    {
                        char_ptr_array_tmp = (char **) realloc(found->values, sizeof(char *) * (found->values_found_count + 1));
                        if (!char_ptr_array_tmp)
                        {
                            return 0;
                        }
                        found->values = char_ptr_array_tmp;
                        found->values_found_count++;
                        found->key_found = 1;
                        found->values[found->jps_found_count] = found->value_placeholder;
                    }
                    break;
                }
                else
                {
                    char_array_tmp = (char *) malloc(sizeof(char) * val->parent->u.object.values[val->parent->u.object.length].name_length + 2);
                    sprintf(char_array_tmp, ".%s", val->parent->u.object.values[val->parent->u.object.length].name);
                    current_jp = prepend_str_const(current_jp, char_array_tmp);
                    free(char_array_tmp);
                    if (!current_jp)
                    {
                        puts("prepend_str_const problem\n");
                    }
                    if (found->check_keys && re_match(found->regex, val->parent->u.object.values[val->parent->u.object.length].name))
                    {
                        char_ptr_array_tmp = (char **) realloc(found->values, sizeof(char *) * (found->values_found_count + 1));
                        if (!char_ptr_array_tmp)
                        {
                            return 0;
                        }
                        found->values = char_ptr_array_tmp;
                        found->values_found_count++;
                        found->values[found->jps_found_count] = val->u.string.ptr;

                        found->key_found = 1;
                        found->values[found->jps_found_count] = found->value_placeholder;
                    }
                    break;
                }
            case json_array:
                char_ptr_array_tmp = (char **) realloc(found->values, sizeof(char *) * (found->values_found_count + 1));
                if (!char_ptr_array_tmp)
                {
                    return 0;
                }
                found->values = char_ptr_array_tmp;
                found->values_found_count++;
                found->values[found->jps_found_count] = found->value_placeholder;
                char_array_tmp = (char *) malloc(sizeof(char) * int_char_length(val->parent->u.array.length) + 4);
                sprintf(char_array_tmp, "[%d]", val->parent->u.array.length);
                char_array_tmp2 = (char *) realloc(current_jp, sizeof(char) * found->jps_longest + int_char_length(val->parent->u.array.length) + 4);
                if (!char_array_tmp2)
                {
                    return 0;
                }
                current_jp = char_array_tmp2;
                current_jp = prepend_str_const(current_jp, char_array_tmp);
                free(char_array_tmp);
                break;
        }
        val = val->parent;
    }
    return current_jp;
}


void build_jsonpath (json_value * val, jp * found)
{
    char * current_jp = NULL;
    char * bool_char;
    char * int_char;
    char ** char_ptr_array_tmp;
    switch (val->type)
    {
        case json_integer:
            int_char = malloc(sizeof(char) * int_char_length(val->u.integer) + 1);
            if (found->jps_longest < found->jps_longest + int_char_length(val->u.integer) + 1)
            {
                found->jps_longest = found->jps_longest + int_char_length(val->u.integer) + 1;
            }
            sprintf(int_char, "%lld", val->u.integer);
            if (re_match(found->regex, int_char))
            {
                char_ptr_array_tmp = (char **) realloc(found->values, sizeof(char *) * (found->values_found_count + 1));
                if (!char_ptr_array_tmp)
                {
                    return;
                }
                found->values = char_ptr_array_tmp;
                found->values_found_count++;
                found->values[found->jps_found_count] = int_char;
                found->value_placeholder = int_char;
                found->value_found = 1;
                char_ptr_array_tmp = (char **) realloc(found->values_free, sizeof(char *) * (found->values_free_count + 1));
                if (!char_ptr_array_tmp)
                {
                    return;
                }
                found->values_free = char_ptr_array_tmp;
                found->values_free[found->values_free_count] = int_char;
                found->values_free_count++;
                current_jp = climb(val, current_jp, found);
            }
            else
            {
                if (found->check_keys)
                {
                    found->value_placeholder = int_char;
                    current_jp = climb(val, current_jp, found);
                    if(!found->key_found)
                    {
                        free(int_char);
                    }
                }
                else
                {
                    free(int_char);
                }

            }
            break;
        case json_double:
            int_char = malloc(sizeof(char) * int_char_length(val->u.dbl) + 25);
            if (found->jps_longest < found->jps_longest + int_char_length(val->u.dbl) + 25)
            {
                found->jps_longest = found->jps_longest + int_char_length(val->u.dbl) + 25;
            }
            sprintf(int_char, "%f", val->u.dbl);
            if (re_match(found->regex, int_char))
            {
                char_ptr_array_tmp = (char **) realloc(found->values, sizeof(char *) * (found->values_found_count + 1));
                if (!char_ptr_array_tmp)
                {
                    return;
                }
                found->values = char_ptr_array_tmp;
                found->values_found_count++;
                found->values[found->jps_found_count] = int_char;
                found->value_placeholder = int_char;
                found->value_found = 1;
                char_ptr_array_tmp = (char **) realloc(found->values_free, sizeof(char *) * (found->values_free_count + 1));
                if (!char_ptr_array_tmp)
                {
                    return;
                }
                found->values_free = char_ptr_array_tmp;
                found->values_free[found->values_free_count] = int_char;
                found->values_free_count++;
                current_jp = climb(val, current_jp, found);
            }
            else
            {
                if (found->check_keys)
                {
                    found->value_placeholder = int_char;
                    current_jp = climb(val, current_jp, found);
                    if(!found->key_found)
                    {
                        free(int_char);
                    }
                }
                else
                {
                    free(int_char);
                }

            }
            break;
        case json_string:
            found->value_placeholder = val->u.string.ptr;
            if (found->jps_longest < found->jps_longest + val->u.string.length + 1)
            {
                found->jps_longest = found->jps_longest + val->u.string.length + 1;
            }
            if (re_match(found->regex, val->u.string.ptr))
            {
                char_ptr_array_tmp = (char **) realloc(found->values, sizeof(char *) * (found->values_found_count + 1));
                if (!char_ptr_array_tmp)
                {
                    return;
                }
                found->values = char_ptr_array_tmp;
                found->values_found_count++;
                found->values[found->jps_found_count] = val->u.string.ptr;
                found->value_found = 1;
                current_jp = climb(val, current_jp, found);
            }
            else
            {
                if (found->check_keys)
                {
                    found->value_placeholder = val->u.string.ptr;
                    current_jp = climb(val, current_jp, found);
                }
            }
            break;
        case json_boolean:
            bool_char = malloc(sizeof(char) * 6);
            if (found->jps_longest < found->jps_longest + 6)
            {
                found->jps_longest = found->jps_longest + 6;
            }
            sprintf(bool_char, "%s", val->u.boolean ? "true" : "false");
            if (re_match(found->regex, bool_char))
            {
                char_ptr_array_tmp = (char **) realloc(found->values, sizeof(char *) * (found->values_found_count + 1));
                if (!char_ptr_array_tmp)
                {
                    return;
                }
                found->values = char_ptr_array_tmp;
                found->values_found_count++;
                found->values[found->jps_found_count] = bool_char;
                found->value_placeholder = bool_char;
                found->value_found = 1;
                char_ptr_array_tmp = (char **) realloc(found->values_free, sizeof(char *) * (found->values_free_count + 1));
                if (!char_ptr_array_tmp)
                {
                    return;
                }
                found->values_free = char_ptr_array_tmp;
                found->values_free[found->values_free_count] = bool_char;
                found->values_free_count++;
                current_jp = climb(val, current_jp, found);
            }
            else
            {
                if (found->check_keys)
                {
                    current_jp = climb(val, current_jp, found);
                    if(!found->key_found)
                    {
                        free(bool_char);
                    }
                }
                else
                {
                    free(bool_char);
                }

            }
            break;
        default:
            return;
    }

    if (found->value_found || found->key_found)
    {
        char ** char_ptr_array_tmp = (char **) realloc(found->jps, sizeof(char *) * (found->jps_found_count + 1));
        if (!char_ptr_array_tmp)
        {
            return;
        }
        found->jps = char_ptr_array_tmp;
        found->jps[found->jps_found_count] = current_jp;
        found->jps_found_count++;
        found->value_found = found->key_found = 0;
    }
    else
    {
        free(current_jp);
    }
}
// end thad mods

static const json_int_t JSON_INT_MAX = sizeof(json_int_t) == 1
                                       ? INT8_MAX
                                       : (sizeof(json_int_t) == 2
                                               ? INT16_MAX
                                               : (sizeof(json_int_t) == 4
                                                       ? INT32_MAX
                                                       : INT64_MAX));

static unsigned char hex_value (json_char c)
{
    if (isdigit(c))
        return c - '0';

    switch (c)
    {
        case 'a':
        case 'A':
            return 0x0A;
        case 'b':
        case 'B':
            return 0x0B;
        case 'c':
        case 'C':
            return 0x0C;
        case 'd':
        case 'D':
            return 0x0D;
        case 'e':
        case 'E':
            return 0x0E;
        case 'f':
        case 'F':
            return 0x0F;
        default:
            return 0xFF;
    }
}

static int would_overflow (json_int_t value, json_char b)
{
    return ((JSON_INT_MAX - (b - '0')) / 10 ) < value;
}

typedef struct
{
    unsigned long used_memory;

    unsigned int uint_max;
    unsigned long ulong_max;

    json_settings settings;
    int first_pass;

    const json_char * ptr;
    unsigned int cur_line, cur_col;

} json_state;

static void * default_alloc (size_t size, int zero, void * user_data)
{
    return zero ? calloc (1, size) : malloc (size);
}

static void default_free (void * ptr, void * user_data)
{
    free (ptr);
}

static void * json_alloc (json_state * state, unsigned long size, int zero)
{
    if ((state->ulong_max - state->used_memory) < size)
        return 0;

    if (state->settings.max_memory
            && (state->used_memory += size) > state->settings.max_memory)
    {
        return 0;
    }

    return state->settings.mem_alloc (size, zero, state->settings.user_data);
}

static int new_value (json_state * state,
                      json_value ** top, json_value ** root, json_value ** alloc,
                      json_type type)
{
    json_value * value;
    int values_size;

    if (!state->first_pass)
    {
        value = *top = *alloc;
        *alloc = (*alloc)->_reserved.next_alloc;

        if (!*root)
            *root = value;

        switch (value->type)
        {
            case json_array:

                if (value->u.array.length == 0)
                    break;

                if (! (value->u.array.values = (json_value **) json_alloc
                                               (state, value->u.array.length * sizeof (json_value *), 0)) )
                {
                    return 0;
                }

                value->u.array.length = 0;
                break;

            case json_object:

                if (value->u.object.length == 0)
                    break;

                values_size = sizeof (*value->u.object.values) * value->u.object.length;

                if (! (value->u.object.values = (json_object_entry *) json_alloc
                                                (state, values_size + ((unsigned long) value->u.object.values), 0)) )
                {
                    return 0;
                }

                value->_reserved.object_mem = (*(char **) &value->u.object.values) + values_size;

                value->u.object.length = 0;
                break;

            case json_string:

                if (! (value->u.string.ptr = (json_char *) json_alloc
                                             (state, (value->u.string.length + 1) * sizeof (json_char), 0)) )
                {
                    return 0;
                }

                value->u.string.length = 0;
                break;

            default:
                break;
        };

        return 1;
    }

    if (! (value = (json_value *) json_alloc
                   (state, sizeof (json_value) + state->settings.value_extra, 1)))
    {
        return 0;
    }

    if (!*root)
        *root = value;

    value->type = type;
    value->parent = *top;

#ifdef JSON_TRACK_SOURCE
    value->line = state->cur_line;
    value->col = state->cur_col;
#endif

    if (*alloc)
        (*alloc)->_reserved.next_alloc = value;

    *alloc = *top = value;

    return 1;
}

#define whitespace \
   case '\n': ++ state.cur_line;  state.cur_col = 0; \
   case ' ': case '\t': case '\r'

#define string_add(b)  \
   do { if (!state.first_pass) string [string_length] = b;  ++ string_length; } while (0);

#define line_and_col \
   state.cur_line, state.cur_col

static const long
flag_next             = 1 << 0,
flag_reproc           = 1 << 1,
flag_need_comma       = 1 << 2,
flag_seek_value       = 1 << 3,
flag_escaped          = 1 << 4,
flag_string           = 1 << 5,
flag_need_colon       = 1 << 6,
flag_done             = 1 << 7,
flag_num_negative     = 1 << 8,
flag_num_zero         = 1 << 9,
flag_num_e            = 1 << 10,
flag_num_e_got_sign   = 1 << 11,
flag_num_e_negative   = 1 << 12,
flag_line_comment     = 1 << 13,
flag_block_comment    = 1 << 14,
flag_num_got_decimal  = 1 << 15;

json_value * json_parse_ex (json_settings * settings,
                            const json_char * json,
                            size_t length,
                            char * error_buf,
                            jp * jp_struct)
{
    json_char error [json_error_max];
    const json_char * end;
    json_value * top, * root, * alloc = 0;
    json_state state = { 0 };
    long flags = 0;
    double num_digits = 0, num_e = 0;
    double num_fraction = 0;

    /* Skip UTF-8 BOM
     */
    if (length >= 3 && ((unsigned char) json [0]) == 0xEF
            && ((unsigned char) json [1]) == 0xBB
            && ((unsigned char) json [2]) == 0xBF)
    {
        json += 3;
        length -= 3;
    }

    error[0] = '\0';
    end = (json + length);

    memcpy (&state.settings, settings, sizeof (json_settings));

    if (!state.settings.mem_alloc)
        state.settings.mem_alloc = default_alloc;

    if (!state.settings.mem_free)
        state.settings.mem_free = default_free;

    memset (&state.uint_max, 0xFF, sizeof (state.uint_max));
    memset (&state.ulong_max, 0xFF, sizeof (state.ulong_max));

    state.uint_max -= 8; /* limit of how much can be added before next check */
    state.ulong_max -= 8;

    for (state.first_pass = 1; state.first_pass >= 0; -- state.first_pass)
    {
        json_uchar uchar;
        unsigned char uc_b1, uc_b2, uc_b3, uc_b4;
        json_char * string = 0;
        unsigned int string_length = 0;

        top = root = 0;
        flags = flag_seek_value;

        state.cur_line = 1;

        for (state.ptr = json ;; ++ state.ptr)
        {
            json_char b = (state.ptr == end ? 0 : *state.ptr);
            int garbage_check;

            if (flags & flag_string)
            {
                if (!b)
                {
                    sprintf (error, "Unexpected EOF in string (at %d:%d)", line_and_col);
                    goto e_failed;
                }

                if (string_length > state.uint_max)
                    goto e_overflow;

                if (flags & flag_escaped)
                {
                    flags &= ~ flag_escaped;

                    switch (b)
                    {
                        case 'b':
                            string_add ('\b');
                            break;
                        case 'f':
                            string_add ('\f');
                            break;
                        case 'n':
                            string_add ('\n');
                            break;
                        case 'r':
                            string_add ('\r');
                            break;
                        case 't':
                            string_add ('\t');
                            break;
                        case 'u':

                            if (end - state.ptr < 4 ||
                                    (uc_b1 = hex_value (*++ state.ptr)) == 0xFF ||
                                    (uc_b2 = hex_value (*++ state.ptr)) == 0xFF ||
                                    (uc_b3 = hex_value (*++ state.ptr)) == 0xFF ||
                                    (uc_b4 = hex_value (*++ state.ptr)) == 0xFF)
                            {
                                sprintf (error, "Invalid character value `%c` (at %d:%d)", b, line_and_col);
                                goto e_failed;
                            }

                            uc_b1 = (uc_b1 << 4) | uc_b2;
                            uc_b2 = (uc_b3 << 4) | uc_b4;
                            uchar = (uc_b1 << 8) | uc_b2;

                            if ((uchar & 0xF800) == 0xD800)
                            {
                                json_uchar uchar2;

                                if (end - state.ptr < 6 || (*++ state.ptr) != '\\' || (*++ state.ptr) != 'u' ||
                                        (uc_b1 = hex_value (*++ state.ptr)) == 0xFF ||
                                        (uc_b2 = hex_value (*++ state.ptr)) == 0xFF ||
                                        (uc_b3 = hex_value (*++ state.ptr)) == 0xFF ||
                                        (uc_b4 = hex_value (*++ state.ptr)) == 0xFF)
                                {
                                    sprintf (error, "Invalid character value `%c` (at %d:%d)", b, line_and_col);
                                    goto e_failed;
                                }

                                uc_b1 = (uc_b1 << 4) | uc_b2;
                                uc_b2 = (uc_b3 << 4) | uc_b4;
                                uchar2 = (uc_b1 << 8) | uc_b2;

                                uchar = 0x010000 | ((uchar & 0x3FF) << 10) | (uchar2 & 0x3FF);
                            }

                            if (sizeof (json_char) >= sizeof (json_uchar) || (uchar <= 0x7F))
                            {
                                string_add ((json_char) uchar);
                                break;
                            }

                            if (uchar <= 0x7FF)
                            {
                                if (state.first_pass)
                                    string_length += 2;
                                else
                                {
                                    string [string_length ++] = 0xC0 | (uchar >> 6);
                                    string [string_length ++] = 0x80 | (uchar & 0x3F);
                                }

                                break;
                            }

                            if (uchar <= 0xFFFF)
                            {
                                if (state.first_pass)
                                    string_length += 3;
                                else
                                {
                                    string [string_length ++] = 0xE0 | (uchar >> 12);
                                    string [string_length ++] = 0x80 | ((uchar >> 6) & 0x3F);
                                    string [string_length ++] = 0x80 | (uchar & 0x3F);
                                }

                                break;
                            }

                            if (state.first_pass)
                                string_length += 4;
                            else
                            {
                                string [string_length ++] = 0xF0 | (uchar >> 18);
                                string [string_length ++] = 0x80 | ((uchar >> 12) & 0x3F);
                                string [string_length ++] = 0x80 | ((uchar >> 6) & 0x3F);
                                string [string_length ++] = 0x80 | (uchar & 0x3F);
                            }

                            break;

                        default:
                            string_add (b);
                    };

                    continue;
                }

                if (b == '\\')
                {
                    flags |= flag_escaped;
                    continue;
                }

                if (b == '"')
                {
                    if (!state.first_pass)
                    {
                        string [string_length] = 0;
                    }

                    flags &= ~ flag_string;
                    string = 0;

                    switch (top->type)
                    {
                        case json_string:

                            top->u.string.length = string_length;
                            flags |= flag_next;

                            break;

                        case json_object:

                            if (state.first_pass)
                                /*
                                18:05 < fizzie> FriedOkra: The cast is into "pointer to pointer to json_char", but since there's a & in the operand to take the address of `values`, and a * in front to dereference it, the effect is basically "pretend that the bytes of `values` are a pointer to a json_char, then increment it".
                                18:06 < fizzie> (Which is most likely to be undefined behavior by a strict interpretation of the standard, unless `values` actually *is* a `json_char *`.)
                                18:13 < FriedOkra> fizzie: ty! gosh trying to interpret the pointing and dereferencing there is making my head spin. do you know of any helpful docs/guides which may help me grok it?
                                 18:19 < FriedOkra> (*(json_char **) &top->u.object.values) += 1; // values is a pointer to json_char and we grab its address and then cast that as pointer to pointer to json_char - that makes sense. I'm confused about the dereferencing happening which makes it just a pointer to json_char? why not increment value directly?
                                18:19 < fizzie> Because what the increment does depends on the pointer type.
                                18:22 < fizzie> So if you had e.g. `int *values;`, if you just say `values += 1;` it increments it to point to a next int object, but if you say `(*(char **)&values) += 1;` it treats the contents of values as if it was a char *, and increments it by one char object.
                                18:22 < fizzie> (Again, this is not strictly conforming.)
                                18:37 < fizzie> The `(*(char**)&v2)++` there is pretty close to being the same as `char *tmp = (char *)v2; tmp++; v2 = (int *)tmp;` except instead of using a temporary variable, it just pretends there's a char * at the address of v2.

                                */

                                (*(json_char **) &top->u.object.values) += string_length + 1;
                            else
                            {
                                top->u.object.values [top->u.object.length].name
                                    = (json_char *) top->_reserved.object_mem;

                                top->u.object.values [top->u.object.length].name_length
                                    = string_length;

                                (*(json_char **) &top->_reserved.object_mem) += string_length + 1;
                            }



                            flags |= flag_seek_value | flag_need_colon;
                            continue;

                        default:
                            break;
                    };
                }
                else
                {
                    string_add (b);
                    continue;
                }
            }

            if (state.settings.settings & json_enable_comments)
            {
                if (flags & (flag_line_comment | flag_block_comment))
                {
                    if (flags & flag_line_comment)
                    {
                        if (b == '\r' || b == '\n' || !b)
                        {
                            flags &= ~ flag_line_comment;
                            -- state.ptr;  /* so null can be reproc'd */
                        }

                        continue;
                    }

                    if (flags & flag_block_comment)
                    {
                        if (!b)
                        {
                            sprintf (error, "%d:%d: Unexpected EOF in block comment", line_and_col);
                            goto e_failed;
                        }

                        if (b == '*' && state.ptr < (end - 1) && state.ptr [1] == '/')
                        {
                            flags &= ~ flag_block_comment;
                            ++ state.ptr;  /* skip closing sequence */
                        }

                        continue;
                    }
                }
                else if (b == '/')
                {
                    if (! (flags & (flag_seek_value | flag_done)) && top->type != json_object)
                    {
                        sprintf (error, "%d:%d: Comment not allowed here", line_and_col);
                        goto e_failed;
                    }

                    if (++ state.ptr == end)
                    {
                        sprintf (error, "%d:%d: EOF unexpected", line_and_col);
                        goto e_failed;
                    }

                    switch (b = *state.ptr)
                    {
                        case '/':
                            flags |= flag_line_comment;
                            continue;

                        case '*':
                            flags |= flag_block_comment;
                            continue;

                        default:
                            sprintf (error, "%d:%d: Unexpected `%c` in comment opening sequence", line_and_col, b);
                            goto e_failed;
                    };
                }
            }

            if (flags & flag_done)
            {
                if (!b)
                    break;

                switch (b)
                {
                    // *INDENT-OFF*
                    whitespace:
                        continue;
                    // *INDENT-ON*

                    default:

                        sprintf (error, "%d:%d: Trailing garbage: `%c`",
                                 state.cur_line, state.cur_col, b);

                        goto e_failed;
                };
            }

            if (flags & flag_seek_value)
            {
                switch (b)
                {
                    // *INDENT-OFF*
                    whitespace:
                        continue;
                    // *INDENT-ON*

                    case ']':

                        if (top && top->type == json_array)
                        {
                            garbage_check = trailing_garbage(state.ptr);
                            if (garbage_check)
                            {
                                sprintf (error, "Trailing garbage before %d:%d",
                                         state.cur_line, state.cur_col);
                                goto e_failed;
                            }
                            flags = (flags & ~ (flag_need_comma | flag_seek_value)) | flag_next;
                        }
                        else
                        {
                            sprintf (error, "%d:%d: Unexpected ]", line_and_col);
                            goto e_failed;
                        }

                        break;

                    default:

                        if (flags & flag_need_comma)
                        {
                            if (b == ',')
                            {
                                flags &= ~ flag_need_comma;
                                continue;
                            }
                            else
                            {
                                sprintf (error, "%d:%d: Expected , before %c",
                                         state.cur_line, state.cur_col, b);

                                goto e_failed;
                            }
                        }

                        if (flags & flag_need_colon)
                        {
                            if (b == ':')
                            {
                                flags &= ~ flag_need_colon;
                                /* printf("colon\n"); */
                                continue;
                            }
                            else
                            {
                                sprintf (error, "%d:%d: Expected : before %c",
                                         state.cur_line, state.cur_col, b);

                                goto e_failed;
                            }
                        }
                        flags &= ~ flag_seek_value;

                        switch (b)
                        {
                            case '{':

                                if (!new_value (&state, &top, &root, &alloc, json_object))
                                    goto e_alloc_failure;

                                continue;

                            case '[':

                                if (!new_value (&state, &top, &root, &alloc, json_array))
                                    goto e_alloc_failure;

                                flags |= flag_seek_value;
                                continue;

                            case '"':

                                if (!new_value (&state, &top, &root, &alloc, json_string))
                                    goto e_alloc_failure;

                                flags |= flag_string;

                                string = top->u.string.ptr;
                                string_length = 0;

                                continue;

                            case 't':

                                if ((end - state.ptr) < 3 || *(++ state.ptr) != 'r' ||
                                        *(++ state.ptr) != 'u' || *(++ state.ptr) != 'e')
                                {
                                    goto e_unknown_value;
                                }

                                if (!new_value (&state, &top, &root, &alloc, json_boolean))
                                    goto e_alloc_failure;

                                top->u.boolean = 1;

                                flags |= flag_next;
                                break;

                            case 'f':

                                if ((end - state.ptr) < 4 || *(++ state.ptr) != 'a' ||
                                        *(++ state.ptr) != 'l' || *(++ state.ptr) != 's' ||
                                        *(++ state.ptr) != 'e')
                                {
                                    goto e_unknown_value;
                                }

                                if (!new_value (&state, &top, &root, &alloc, json_boolean))
                                    goto e_alloc_failure;

                                flags |= flag_next;
                                break;

                            case 'n':

                                if ((end - state.ptr) < 3 || *(++ state.ptr) != 'u' ||
                                        *(++ state.ptr) != 'l' || *(++ state.ptr) != 'l')
                                {
                                    goto e_unknown_value;
                                }

                                if (!new_value (&state, &top, &root, &alloc, json_null))
                                    goto e_alloc_failure;

                                flags |= flag_next;
                                break;

                            default:

                                if (isdigit (b) || b == '-')
                                {
                                    if (!new_value (&state, &top, &root, &alloc, json_integer))
                                        goto e_alloc_failure;

                                    if (!state.first_pass)
                                    {
                                        while (isdigit (b) || b == '+' || b == '-'
                                                || b == 'e' || b == 'E' || b == '.')
                                        {
                                            if ( (++ state.ptr) == end)
                                            {
                                                b = 0;
                                                break;
                                            }

                                            b = *state.ptr;
                                        }

                                        flags |= flag_next | flag_reproc;
                                        break;
                                    }

                                    flags &= ~ (flag_num_negative | flag_num_e |
                                                flag_num_e_got_sign | flag_num_e_negative |
                                                flag_num_zero);

                                    num_digits = 0;
                                    num_fraction = 0;
                                    num_e = 0;

                                    if (b != '-')
                                    {
                                        flags |= flag_reproc;
                                        break;
                                    }

                                    flags |= flag_num_negative;
                                    continue;
                                }
                                else
                                {
                                    sprintf (error, "%d:%d: Unexpected %c when seeking value", line_and_col, b);
                                    goto e_failed;
                                }
                        };
                };
            }
            else
            {
                switch (top->type)
                {
                    case json_object:

                        switch (b)
                        {
                            // *INDENT-OFF*
                            whitespace:
                                continue;
                            // *INDENT-ON*

                            case '"':

                                if (flags & flag_need_comma)
                                {
                                    sprintf (error, "%d:%d: Expected , before \"", line_and_col);
                                    goto e_failed;
                                }

                                flags |= flag_string;

                                string = (json_char *) top->_reserved.object_mem;
                                string_length = 0;

                                break;

                            case '}':

                                garbage_check = trailing_garbage(state.ptr);
                                if (garbage_check)
                                {
                                    sprintf (error, "Trailing garbage before %d:%d",
                                             state.cur_line, state.cur_col);
                                    goto e_failed;
                                }

                                flags = (flags & ~ flag_need_comma) | flag_next;
                                break;

                            case ',':

                                if (flags & flag_need_comma)
                                {
                                    flags &= ~ flag_need_comma;
                                    break;
                                }

                            default:
                                sprintf (error, "%d:%d: Unexpected `%c` in object", line_and_col, b);
                                goto e_failed;
                        };

                        break;

                    case json_integer:
                    case json_double:

                        if (isdigit (b))
                        {
                            ++ num_digits;

                            if (top->type == json_integer || flags & flag_num_e)
                            {
                                if (! (flags & flag_num_e))
                                {
                                    if (flags & flag_num_zero)
                                    {
                                        sprintf (error, "%d:%d: Unexpected `0` before `%c`", line_and_col, b);
                                        goto e_failed;
                                    }

                                    if (num_digits == 1 && b == '0')
                                        flags |= flag_num_zero;
                                }
                                else
                                {
                                    flags |= flag_num_e_got_sign;
                                    num_e = (num_e * 10) + (b - '0');
                                    continue;
                                }

                                if (would_overflow(top->u.integer, b))
                                {
                                    -- num_digits;
                                    -- state.ptr;
                                    top->type = json_double;
                                    top->u.dbl = (double)top->u.integer;
                                    continue;
                                }

                                top->u.integer = (top->u.integer * 10) + (b - '0');
                                continue;
                            }

                            if (flags & flag_num_got_decimal)
                                num_fraction = (num_fraction * 10) + (b - '0');
                            else
                                top->u.dbl = (top->u.dbl * 10) + (b - '0');

                            continue;
                        }

                        if (b == '+' || b == '-')
                        {
                            if ( (flags & flag_num_e) && !(flags & flag_num_e_got_sign))
                            {
                                flags |= flag_num_e_got_sign;

                                if (b == '-')
                                    flags |= flag_num_e_negative;

                                continue;
                            }
                        }
                        else if (b == '.' && top->type == json_integer)
                        {
                            if (!num_digits)
                            {
                                sprintf (error, "%d:%d: Expected digit before `.`", line_and_col);
                                goto e_failed;
                            }

                            top->type = json_double;
                            top->u.dbl = (double) top->u.integer;

                            flags |= flag_num_got_decimal;
                            num_digits = 0;
                            continue;
                        }

                        if (! (flags & flag_num_e))
                        {
                            if (top->type == json_double)
                            {
                                if (!num_digits)
                                {
                                    sprintf (error, "%d:%d: Expected digit after `.`", line_and_col);
                                    goto e_failed;
                                }

                                top->u.dbl += num_fraction / pow (10.0, num_digits);
                            }

                            if (b == 'e' || b == 'E')
                            {
                                flags |= flag_num_e;

                                if (top->type == json_integer)
                                {
                                    top->type = json_double;
                                    top->u.dbl = (double) top->u.integer;
                                }

                                num_digits = 0;
                                flags &= ~ flag_num_zero;

                                continue;
                            }
                        }
                        else
                        {
                            if (!num_digits)
                            {
                                sprintf (error, "%d:%d: Expected digit after `e`", line_and_col);
                                goto e_failed;
                            }

                            top->u.dbl *= pow (10.0, (flags & flag_num_e_negative ? - num_e : num_e));
                        }

                        if (flags & flag_num_negative)
                        {
                            if (top->type == json_integer)
                                top->u.integer = - top->u.integer;
                            else
                                top->u.dbl = - top->u.dbl;
                        }

                        flags |= flag_next | flag_reproc;
                        break;

                    default:
                        break;
                };
            }

            if (flags & flag_reproc)
            {
                flags &= ~ flag_reproc;
                -- state.ptr;
            }

            if (flags & flag_next)
            {
                flags = (flags & ~ flag_next) | flag_need_comma;

                if (!top->parent)
                {
                    /* root value done */

                    flags |= flag_done;
                    continue;
                }

                if (top->parent->type == json_array)
                    flags |= flag_seek_value;

                if (!state.first_pass)
                {
                    json_value * parent = top->parent;

                    switch (parent->type)
                    {
                        case json_object:

                            parent->u.object.values
                            [parent->u.object.length].value = top;
                            build_jsonpath(top, jp_struct);
                            break;

                        case json_array:

                            parent->u.array.values
                            [parent->u.array.length] = top;
                            build_jsonpath(top, jp_struct);

                            break;

                        default:
                            break;
                    };
                }

                if ( (++ top->parent->u.array.length) > state.uint_max)
                    goto e_overflow;

                // top moves up one
                top = top->parent;

                continue;
            }
        }

        alloc = root;
        // build non-object/array jsonpaths
        if (!alloc->parent && !state.first_pass)
        {
            char * bool_char;
            char * int_char;
            char * single_jp;
            switch(alloc->type)
            {
                case json_boolean:
                    single_jp = malloc(sizeof(char) * 2);
                    single_jp = strcpy(single_jp, ".");
                    bool_char = malloc(sizeof(char) * 6);
                    sprintf(bool_char, "%s", alloc->u.boolean ? "true" : "false");
                    if (re_match(jp_struct->regex, bool_char))
                    {
                        char ** char_ptr_array_tmp = (char **) realloc(jp_struct->jps, sizeof(char *) * (jp_struct->jps_found_count + 1));
                        if (!char_ptr_array_tmp)
                        {
                            goto e_failed;
                        }
                        jp_struct->jps = char_ptr_array_tmp;
                        jp_struct->jps[jp_struct->jps_found_count] = single_jp;
                        jp_struct->jps_found_count++;

                        char_ptr_array_tmp = (char **) realloc(jp_struct->values, sizeof(char *) * (jp_struct->values_found_count + 1));
                        if (!char_ptr_array_tmp)
                        {
                            goto e_failed;
                        }
                        jp_struct->values = char_ptr_array_tmp;
                        jp_struct->values[jp_struct->values_found_count] = bool_char;
                        jp_struct->values_found_count++;
                        jp_struct->value_placeholder = bool_char;
                        char_ptr_array_tmp = (char **) realloc(jp_struct->values_free, sizeof(char *) * (jp_struct->values_free_count + 1));
                        if (!char_ptr_array_tmp)
                        {
                            goto e_failed;
                        }
                        jp_struct->values_free = char_ptr_array_tmp;
                        jp_struct->values_free[jp_struct->values_free_count] = bool_char;
                        jp_struct->values_free_count++;
                    }
                    else
                    {
                        free(bool_char);
                        free(single_jp);
                    }
                    break;
                case json_string:
                    single_jp = malloc(sizeof(char) * 2);
                    single_jp = strcpy(single_jp, ".");
                    if (re_match(jp_struct->regex, alloc->u.string.ptr))
                    {
                        char ** char_ptr_array_tmp = (char **) realloc(jp_struct->jps, sizeof(char *) * (jp_struct->jps_found_count + 1));
                        if (!char_ptr_array_tmp)
                        {
                            goto e_failed;
                        }
                        jp_struct->jps = char_ptr_array_tmp;
                        jp_struct->jps[jp_struct->jps_found_count] = single_jp;
                        jp_struct->jps_found_count++;

                        char_ptr_array_tmp = (char **) realloc(jp_struct->values, sizeof(char *) * (jp_struct->values_found_count + 1));
                        if (!char_ptr_array_tmp)
                        {
                            goto e_failed;
                        }
                        jp_struct->values = char_ptr_array_tmp;
                        jp_struct->values[jp_struct->values_found_count] = alloc->u.string.ptr;
                        jp_struct->values_found_count++;
                        jp_struct->value_placeholder = alloc->u.string.ptr;
                    }
                    else
                    {
                        free(single_jp);
                    }
                    break;
                case json_integer:
                case json_double:
                    single_jp = malloc(sizeof(char) * 2);
                    single_jp = strcpy(single_jp, ".");
                    int_char = malloc(sizeof(char) * int_char_length(alloc->u.integer) + 1);
                    sprintf(int_char, "%lld", alloc->u.integer);
                    if (re_match(jp_struct->regex, int_char))
                    {
                        char ** char_ptr_array_tmp = (char **) realloc(jp_struct->jps, sizeof(char *) * (jp_struct->jps_found_count + 1));
                        if (!char_ptr_array_tmp)
                        {
                            goto e_failed;
                        }
                        jp_struct->jps = char_ptr_array_tmp;
                        jp_struct->jps[jp_struct->jps_found_count] = single_jp;
                        jp_struct->jps_found_count++;

                        char_ptr_array_tmp = (char **) realloc(jp_struct->values, sizeof(char *) * (jp_struct->values_found_count + 1));
                        if (!char_ptr_array_tmp)
                        {
                            goto e_failed;
                        }
                        jp_struct->values = char_ptr_array_tmp;
                        jp_struct->values[jp_struct->values_found_count] = int_char;
                        jp_struct->values_found_count++;
                        jp_struct->value_placeholder = int_char;
                        char_ptr_array_tmp = (char **) realloc(jp_struct->values_free, sizeof(char *) * (jp_struct->values_free_count + 1));
                        if (!char_ptr_array_tmp)
                        {
                            goto e_failed;
                        }
                        jp_struct->values_free = char_ptr_array_tmp;
                        jp_struct->values_free[jp_struct->values_free_count] = int_char;
                        jp_struct->values_free_count++;
                    }
                    else
                    {
                        free(int_char);
                        free(single_jp);
                    }
                    break;
            }
        }
    }

    root->jsonpath_results = jp_struct;
    return root;

e_unknown_value:

    sprintf (error, "%d:%d: Unknown value", line_and_col);
    goto e_failed;

e_alloc_failure:

    strcpy (error, "Memory allocation failure");
    goto e_failed;

e_overflow:

    sprintf (error, "%d:%d: Too long (caught overflow)", line_and_col);
    goto e_failed;

e_failed:

    if (error_buf)
    {
        if (*error)
            strcpy (error_buf, error);
        else
            strcpy (error_buf, "Unknown error");
    }

    if (state.first_pass)
        alloc = root;

    while (alloc)
    {
        top = alloc->_reserved.next_alloc;
        state.settings.mem_free (alloc, state.settings.user_data);
        alloc = top;
    }

    if (!state.first_pass)
        json_value_free_ex (&state.settings, root);

    return 0;
}

json_value * json_parse (const json_char * json, size_t length, arguments arguments)
{

    // new main code going here
    json_value * value;
    jp * found = (jp *) malloc(1 * sizeof(jp));
    /* found->check_keys = 1; */
    /* found->show_values = 1; */
    /* found->regex = malloc(sizeof(char) * 100); */
    /* strcpy(found->regex, "tru|123"); */
    found->check_keys = arguments.keys;
    found->show_values = arguments.values;
    found->regex = arguments.pcre2;

    found->key_found = 0;
    found->value_found = 0;
    found->values_free_count = 0;
    found->jps_longest = 1;
    found->jps = (char **) malloc(1 * sizeof(char *));
    found->values = (char **) malloc(1 * sizeof(char *));
    found->values_free = (char **) malloc(1 * sizeof(char *));
    found->jps_found_count = 0;
    found->values_found_count = 0;
    json_settings settings = { 0 };
    value = json_parse_ex (&settings, json, length, 0, found);
    return value;
}

void json_value_free_ex (json_settings * settings, json_value * value)
{
    for (int i=0; i < value->jsonpath_results->jps_found_count; i++)
    {
        free(value->jsonpath_results->jps[i]);
    }
    for (int i=0; i < value->jsonpath_results->values_free_count; i++)
    {
        free(value->jsonpath_results->values_free[i]);
    }
    free(value->jsonpath_results->jps);
    free(value->jsonpath_results->values);
    /* free(value->jsonpath_results->regex); */
    free(value->jsonpath_results->values_free);
    free(value->jsonpath_results);
    json_value * cur_value;

    if (!value)
        return;

    value->parent = 0;

    while (value)
    {
        switch (value->type)
        {
            case json_array:

                if (!value->u.array.length)
                {
                    settings->mem_free (value->u.array.values, settings->user_data);
                    break;
                }

                value = value->u.array.values [-- value->u.array.length];
                continue;

            case json_object:

                if (!value->u.object.length)
                {
                    settings->mem_free (value->u.object.values, settings->user_data);
                    break;
                }

                value = value->u.object.values [-- value->u.object.length].value;
                continue;

            case json_string:

                settings->mem_free (value->u.string.ptr, settings->user_data);
                break;

            default:
                break;
        };

        cur_value = value;
        value = value->parent;
        settings->mem_free (cur_value, settings->user_data);
    }
}

void json_value_free (json_value * value)
{
    json_settings settings = { 0 };
    settings.mem_free = default_free;
    json_value_free_ex (&settings, value);
}

int trailing_garbage (const json_char * ptr)
{
    json_char marker = *ptr;
    do
    {
        ptr--;
    }
    while (isspace(*ptr));

    switch (*ptr)
    {
        case '}':
        case '{':
        case ']':
        case '[':
        case '"':
            return 0;

        case 'e':
            marker = *(--ptr);
            if (marker == 's')
            {
                if (*(--ptr) == 'l' && *(--ptr) == 'a' && *(--ptr) == 'f')
                {
                    return 0;
                }
            }
            if (marker == 'u')
            {
                if (*(--ptr) == 'r' && *(--ptr) == 't')
                {
                    return 0;
                }
            }

            return 1;

        case 'l':
            if (*(--ptr) == 'l' && *(--ptr) == 'u' && *(--ptr) == 'n')
            {
                return 0;
            }
            else
            {
                return 1;
            }

        default:
            if (isdigit(*ptr))
            {
                return 0;
            }
            else
            {
                return 1;
            }
    }
}
