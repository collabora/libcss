// test/testutils.c
#include "testutils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

void __assert2(const char *expr, const char *file, int line, const char *function)
{
    fprintf(stderr, "Assertion failed: %s (%s: %s: %d)\n",
            expr, file, function, line);
    abort();
}

bool css__parse_testfile(const char *filename, bool (*callback)(const char *, size_t, void *), void *pw)
{
    FILE *fp;
    char line[1024];
    bool ret = true;

    fp = fopen(filename, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to open %s: %s\n", filename, strerror(errno));
        return false;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        size_t len = strlen(line);
        // Keep newline
        if (!callback(line, len, pw)) {
            ret = false;
            break;
        }
    }

    fclose(fp);
    return ret;
}

char *css__parse_strnchr(const char *s, int c, size_t len)
{
    while (len > 0) {
        if (*s == c)
            return (char *)s;
        s++;
        len--;
    }
    return NULL;
}

size_t css__parse_filesize(const char *s)
{
    size_t size = 0;
    char *end;

    size = strtoul(s, &end, 10);

    if (*end == 'k' || *end == 'K')
        size *= 1024;
    else if (*end == 'm' || *end == 'M')
        size *= 1024 * 1024;

    return size;
}

size_t css__get_file_size(const char *filename)
{
    FILE *fp;
    size_t len = 0;

    fp = fopen(filename, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Failed opening %s: %s\n", filename, strerror(errno));
        return 0;
    }

    fseek(fp, 0, SEEK_END);
    len = ftell(fp);

    fclose(fp);

    return len;
}

css_error css_error_from_string(const char *s)
{
    if (strcmp(s, "CSS_OK") == 0)
        return CSS_OK;
    if (strcmp(s, "CSS_NOMEM") == 0)
        return CSS_NOMEM;
    if (strcmp(s, "CSS_BADPARM") == 0)
        return CSS_BADPARM;
    if (strcmp(s, "CSS_INVALID") == 0)
        return CSS_INVALID;
    if (strcmp(s, "CSS_FILENOTFOUND") == 0)
        return CSS_FILENOTFOUND;
    if (strcmp(s, "CSS_NEEDDATA") == 0)
        return CSS_NEEDDATA;
    if (strcmp(s, "CSS_BADCHARSET") == 0)
        return CSS_BADCHARSET;
    if (strcmp(s, "CSS_EOF") == 0)
        return CSS_EOF;
    if (strcmp(s, "CSS_IMPORTS_PENDING") == 0)
        return CSS_IMPORTS_PENDING;
    if (strcmp(s, "CSS_PROPERTY_NOT_SET") == 0)
        return CSS_PROPERTY_NOT_SET;

    fprintf(stderr, "Unknown error code: %s\n", s);
    return CSS_INVALID;
}