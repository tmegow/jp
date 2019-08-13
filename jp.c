// JP - search json with pcre2
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <argp.h>

#include "json.h"

const char *argp_program_version = "jp 1.0";
static char doc[] = "Search json with pcre2\nWhen [FILE] is -, read standard input";
static char args_doc[] = "FILE PCRE2_EXP";
static struct argp_option options[] =
{
    { "keys", 'k', 0, 0, "Search keys"},
    { "values", 'v', 0, 0, "Show results values"},
    { 0 }
};

static error_t parse_opt(int key, char * arg, struct argp_state * state)
{
    struct arguments * arguments = state->input;
    switch (key)
    {
        case 'k':
            arguments->keys = 1;
            break;
        case 'v':
            arguments->values = 1;
            break;
        case ARGP_KEY_ARG:
            if (arguments->arg_count == 1)
            {
                arguments->pcre2 = arg;
            }
            else if (arguments->arg_count == 2)
            {
                if (*arg == '-')
                {
                    arguments->stdin = 1;
                }
                else
                {
                    arguments->filename = arg;
                }
            }
            (arguments->arg_count)--;
            break;
        case ARGP_KEY_END:
        {
            if (arguments->arg_count >= 1)
            {
                argp_failure (state, 1, 0, "too few arguments");
            }
            else if (arguments->arg_count < 0)
            {
                argp_failure (state, 1, 0, "too many arguments");
            }

        }
        break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, "file" };

int main(int argc, char *argv[])
{
    struct arguments arguments;

    arguments.keys = 0;
    arguments.values = 0;
    arguments.stdin = 0;
    arguments.arg_count = 2;

    argp_parse(&argp, argc, argv, 0, 0, &arguments);
    FILE * fp;
    struct stat filestatus;
    int file_size;
    char * file_contents;
    json_char * json;
    json_value * value;
    char *str;
    char *str_tmp;

    if (arguments.stdin)
    {
        int c;
        int i;
        int size = 10;
        str = malloc(size*sizeof(char));
        for(i=0; (c=getchar()) !='\0' && c != EOF; ++i)
        {
            if( i == size)
            {
                size = 2*size;
                str = realloc(str, size*sizeof(char));
                if(str == NULL)
                {
                    printf("Error Unable to Grow String! :(");
                    exit(-1);
                }
            }
            str[i] = c;
        }
        if(i == size)
        {
            str_tmp = realloc(str, (size+1)*sizeof(char));
            if(str_tmp == NULL)
            {
                printf("Error Unable to Grow String! :(");
                exit(-1);
            }
            str = str_tmp;

        }
        str[i] = '\0';
        json = (json_char*)str;

        value = json_parse(json,size,arguments);

        if (value == NULL)
        {
            fprintf(stderr, "Unable to parse data\n");
            free(file_contents);
            exit(1);
        }
    }
    else
    {


        if ( stat(arguments.filename, &filestatus) != 0)
        {
            fprintf(stderr, "File %s not found\n", arguments.filename);
            return 1;
        }
        file_size = filestatus.st_size;
        file_contents = (char*)malloc(filestatus.st_size);
        if ( file_contents == NULL)
        {
            fprintf(stderr, "Memory error: unable to allocate %d bytes\n", file_size);
            return 1;
        }

        fp = fopen(arguments.filename, "rt");
        if (fp == NULL)
        {
            fprintf(stderr, "Error opening file %s\n", arguments.filename);
            fclose(fp);
            free(file_contents);
            return 1;
        }
        if ( fread(file_contents, file_size, 1, fp) != 1 )
        {
            fprintf(stderr, "Error reading file %s\n", arguments.filename);
            fclose(fp);
            free(file_contents);
            return 1;
        }
        fclose(fp);

        json = (json_char*)file_contents;

        value = json_parse(json,file_size,arguments);

        if (value == NULL)
        {
            fprintf(stderr, "Unable to parse data\n");
            free(file_contents);
            exit(1);
        }
    }

    for (int i=0; i < value->jsonpath_results->jps_found_count; i++)
    {
        if (value->jsonpath_results->show_values)
        {
            printf("JP %d: %s\n", i, value->jsonpath_results->jps[i]);
            printf("Value %d: %s\n", i, value->jsonpath_results->values[i]);
        }
        else
        {
            printf("%s\n", value->jsonpath_results->jps[i]);
        }

    }

    json_value_free(value);
    if (arguments.stdin)
    {
        free(str);
    }
    else
    {
        free(file_contents);
    }
    return 0;
}
