#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <libcss/libcss.h>

#include "utils/utils.h"

#include "testutils.h"

typedef struct line_ctx {
    size_t buflen;
    size_t bufused;
    uint8_t *buf;

    size_t explen;
    char exp[256];

    bool indata;
    bool inexp;
} line_ctx;

static bool handle_line(const char *data, size_t datalen, void *pw);
static void run_test(const uint8_t *data, size_t len, const char *exp, size_t explen);
static void print_css_fixed(char *buf, size_t len, css_fixed f);

int main(int argc, char **argv)
{
    line_ctx ctx;

    if (argc != 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    printf("DEBUG: Loading test file: %s\n", argv[1]);

    ctx.buflen = css__get_file_size(argv[1]);
    if (ctx.buflen == 0) {
        printf("ERROR: Failed to get file size for %s\n", argv[1]);
        return 1;
    }

    ctx.buf = malloc(ctx.buflen);
    if (ctx.buf == NULL) {
        printf("ERROR: Failed allocating %u bytes\n", (unsigned int) ctx.buflen);
        return 1;
    }

    ctx.buf[0] = '\0';
    ctx.bufused = 0;
    ctx.explen = 0;
    ctx.indata = false;
    ctx.inexp = false;

    printf("DEBUG: Parsing test file with size %zu bytes\n", ctx.buflen);
    bool parse_result = css__parse_testfile(argv[1], handle_line, &ctx);
    if (!parse_result) {
        printf("ERROR: Failed to parse test file %s\n", argv[1]);
        free(ctx.buf);
        return 1;
    }

    /* Run final test */
    if (ctx.bufused > 0) {
        printf("DEBUG: Running final test case\n");
        run_test(ctx.buf, ctx.bufused - 1, ctx.exp, ctx.explen);
    } else {
        printf("DEBUG: No final test case to run\n");
    }

    free(ctx.buf);

    printf("PASS\n");
    return 0;
}

bool handle_line(const char *data, size_t datalen, void *pw)
{
    line_ctx *ctx = (line_ctx *) pw;

    printf("DEBUG: Processing line: '%.*s' (len=%zu)\n", (int) datalen, data, datalen);

    if (data[0] == '#') {
        printf("DEBUG: Comment line detected\n");
        if (ctx->inexp) {
            /* End of test case, run it */
            printf("DEBUG: End of test case, running test\n");
            run_test(ctx->buf, ctx->bufused - 1, ctx->exp, ctx->explen);

            ctx->buf[0] = '\0';
            ctx->bufused = 0;
            ctx->explen = 0;
        }

        if (ctx->indata && strncasecmp(data + 1, "expected", 8) == 0) {
            printf("DEBUG: Switching from data to expected\n");
            ctx->indata = false;
            ctx->inexp = true;
        } else if (!ctx->indata) {
            ctx->indata = (strncasecmp(data + 1, "data", 4) == 0);
            ctx->inexp = (strncasecmp(data + 1, "expected", 8) == 0);
            printf("DEBUG: Setting indata=%d, inexp=%d\n", ctx->indata, ctx->inexp);
        } else {
            printf("DEBUG: Appending comment to data buffer\n");
            memcpy(ctx->buf + ctx->bufused, data, datalen);
            ctx->bufused += datalen;
        }
    } else {
        if (ctx->indata) {
            printf("DEBUG: Appending %zu bytes to data buffer\n", datalen);
            memcpy(ctx->buf + ctx->bufused, data, datalen);
            ctx->bufused += datalen;
        }
        if (ctx->inexp) {
            if (data[datalen - 1] == '\n')
                datalen -= 1;
            printf("DEBUG: Setting expected result: '%.*s' (len=%zu)\n", (int) datalen, data, datalen);
            memcpy(ctx->exp, data, datalen);
            ctx->explen = datalen;
        }
    }

    return true;
}

void run_test(const uint8_t *data, size_t len, const char *exp, size_t explen)
{
    lwc_string *in;
    size_t consumed;
    css_fixed result;
    char buf[256];

    printf("DEBUG: Running test with input: '%.*s' (len=%zu)\n", (int) len, data, len);
    printf("DEBUG: Expected output: '%.*s' (len=%zu)\n", (int) explen, exp, explen);

    lwc_error err = lwc_intern_string((const char *) data, len, &in);
    if (err != lwc_error_ok) {
        printf("ERROR: lwc_intern_string failed with error %d\n", err);
        assert(0 && "lwc_intern_string failed");
    }

    result = css__number_from_lwc_string(in, false, &consumed);
    printf("DEBUG: Parsed result=%d, consumed=%zu\n", result, consumed);

    print_css_fixed(buf, sizeof(buf), result);
    printf("DEBUG: Formatted result: '%s'\n", buf);

    if (strncmp(buf, exp, explen) != 0) {
        printf("ERROR: Mismatch - got: '%s' expected: '%.*s'\n", buf, (int) explen, exp);
    }

    assert(strncmp(buf, exp, explen) == 0);

    lwc_string_unref(in);
}

void print_css_fixed(char *buf, size_t len, css_fixed f)
{
#define ABS(x) (uint32_t)((x) < 0 ? -((int64_t)x) : (x))
    uint32_t uintpart = FIXTOINT(ABS(f));
    /* + 500 to ensure round to nearest (division will truncate) */
    uint32_t fracpart = ((ABS(f) & 0x3ff) * 1000 + 500) / (1 << 10);
#undef ABS
    size_t flen = 0;
    char tmp[20];
    size_t tlen = 0;

    printf("DEBUG: print_css_fixed: f=%d, uintpart=%u, fracpart=%u\n", f, uintpart, fracpart);

    if (len == 0)
        return;

    if (f < 0) {
        buf[0] = '-';
        buf++;
        len--;
    }

    do {
        tmp[tlen] = "0123456789"[uintpart % 10];
        tlen++;
        uintpart /= 10;
    } while (tlen < 20 && uintpart != 0);

    while (len > 0 && tlen > 0) {
        buf[0] = tmp[--tlen];
        buf++;
        len--;
    }

    if (len > 0) {
        buf[0] = '.';
        buf++;
        len--;
    }

    do {
        tmp[tlen] = "0123456789"[fracpart % 10];
        tlen++;
        fracpart /= 10;
    } while (tlen < 20 && fracpart != 0);

    while (len > 0 && tlen > 0) {
        buf[0] = tmp[--tlen];
        buf++;
        len--;
        flen++;
    }

    while (len > 0 && flen < 3) {
        buf[0] = '0';
        buf++;
        len--;
        flen++;
    }

    if (len > 0) {
        buf[0] = '\0';
        buf++;
        len--;
    }
}