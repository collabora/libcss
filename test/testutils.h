#ifndef TEST_TESTUTILS_H_
#define TEST_TESTUTILS_H_

#include <stdbool.h>
#include <libcss/libcss.h>

#ifndef UNUSED
#define UNUSED(x) ((x) = (x))
#endif

#define assert(expr) \
  ((void) ((expr) || (__assert2 (#expr, __FILE__, __LINE__, __func__), 0)))

typedef bool (*line_func)(const char *data, size_t datalen, void *pw);

void __assert2(const char *expr, const char *file, int line, const char *function);
bool css__parse_testfile(const char *filename, line_func callback, void *pw);
char *css__parse_strnchr(const char *s, int c, size_t len);
size_t css__parse_filesize(const char *s);
size_t css__get_file_size(const char *filename);
css_error css_error_from_string(const char *s);

#endif