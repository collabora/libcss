#include <ctype.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libcss/libcss.h>

#include "utils/utils.h"

#include "dump.h"
#include "testutils.h"

/** \todo at some point, we need to extend this to handle nested blocks */
typedef struct line_ctx {
    size_t buflen;
    size_t bufused;
    uint8_t *buf;

    size_t explen;
    size_t expused;
    char *exp;

    bool indata;
    bool inerrors;
    bool inexp;

    bool inrule;
} line_ctx;

static bool handle_line(const char *data, size_t datalen, void *pw);
static void css__parse_expected(line_ctx *ctx, const char *data, size_t len);
static void run_test(const uint8_t *data, size_t len,
        const char *exp, size_t explen);

static css_error resolve_url(void *pw,
        const char *base, lwc_string *rel, lwc_string **abs)
{
    UNUSED(pw);
    UNUSED(base);

    /* About as useless as possible */
    *abs = lwc_string_ref(rel);

    return CSS_OK;
}

static bool fail_because_lwc_leaked = false;

static void
printing_lwc_iterator(lwc_string *str, void *pw)
{
    UNUSED(pw);

    printf(" DICT: %*s\n", (int)(lwc_string_length(str)), lwc_string_data(str));
    fail_because_lwc_leaked = true;
}

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
        printf("ERROR: Failed allocating %u bytes\n",
                (unsigned int) ctx.buflen);
        return 1;
    }

    ctx.buf[0] = '\0';
    ctx.bufused = 0;
    ctx.explen = 0;
    ctx.expused = 0;
    ctx.exp = NULL;
    ctx.indata = false;
    ctx.inerrors = false;
    ctx.inexp = false;

    printf("DEBUG: Parsing test file with size %zu bytes\n", ctx.buflen);
    bool parse_result = css__parse_testfile(argv[1], handle_line, &ctx);
    if (!parse_result) {
        printf("ERROR: Failed to parse test file %s\n", argv[1]);
        free(ctx.buf);
        return 1;
    }

    /* and run final test */
    if (ctx.bufused > 0) {
        printf("DEBUG: Running final test case\n");
        run_test(ctx.buf, ctx.bufused, ctx.exp, ctx.expused);
    } else {
        printf("DEBUG: No final test case to run\n");
    }

    free(ctx.buf);
    free(ctx.exp);

    lwc_iterate_strings(printing_lwc_iterator, NULL);

    assert(fail_because_lwc_leaked == false);

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
            /* This marks end of testcase, so run it */
            printf("DEBUG: End of test case, running test\n");
            run_test(ctx->buf, ctx->bufused,
                    ctx->exp, ctx->expused);

            ctx->buf[0] = '\0';
            ctx->bufused = 0;

            ctx->expused = 0;
        }

        if (ctx->indata && strncasecmp(data+1, "errors", 6) == 0) {
            printf("DEBUG: Switching from data to errors\n");
            ctx->indata = false;
            ctx->inerrors = true;
            ctx->inexp = false;
        } else if (ctx->inerrors &&
                strncasecmp(data+1, "expected", 8) == 0) {
            printf("DEBUG: Switching from errors to expected\n");
            ctx->indata = false;
            ctx->inerrors = false;
            ctx->inexp = true;
            ctx->inrule = false;
        } else if (ctx->inexp && strncasecmp(data+1, "data", 4) == 0) {
            printf("DEBUG: Switching from expected to data\n");
            ctx->indata = true;
            ctx->inerrors = false;
            ctx->inexp = false;
        } else if (ctx->indata) {
            printf("DEBUG: Appending comment to data buffer\n");
            memcpy(ctx->buf + ctx->bufused, data, datalen);
            ctx->bufused += datalen;
        } else {
            ctx->indata = (strncasecmp(data+1, "data", 4) == 0);
            ctx->inerrors = (strncasecmp(data+1, "errors", 6) == 0);
            ctx->inexp = (strncasecmp(data+1, "expected", 8) == 0);
            printf("DEBUG: Setting indata=%d, inerrors=%d, inexp=%d\n",
                   ctx->indata, ctx->inerrors, ctx->inexp);
        }
    } else {
        if (ctx->indata) {
            printf("DEBUG: Appending %zu bytes to data buffer\n", datalen);
            memcpy(ctx->buf + ctx->bufused, data, datalen);
            ctx->bufused += datalen;
        }
        if (ctx->inexp) {
            printf("DEBUG: Parsing expected: '%.*s' (len=%zu)\n",
                   (int) datalen, data, datalen);
            css__parse_expected(ctx, data, datalen);
        }
    }

    return true;
}

void css__parse_expected(line_ctx *ctx, const char *data, size_t len)
{
    while (ctx->expused + len >= ctx->explen) {
        size_t required = ctx->explen == 0 ? 64 : ctx->explen * 2;
        char *temp = realloc(ctx->exp, required);
        if (temp == NULL) {
            printf("ERROR: No memory for expected output\n");
            assert(0 && "No memory for expected output");
        }

        ctx->exp = temp;
        ctx->explen = required;
    }

    memcpy(ctx->exp + ctx->expused, data, len);

    ctx->expused += len;
}

void run_test(const uint8_t *data, size_t len, const char *exp, size_t explen)
{
    css_stylesheet_params params;
    css_stylesheet *sheet;
    css_error error;
    char *buf;
    size_t buflen;
    static int testnum;

    printf("DEBUG: Running test with input data (%zu bytes): '%.*s'\n",
           len, (int) len, data);
    printf("DEBUG: Expected output (%zu bytes): '%.*s'\n",
           explen, (int) explen, exp);

    buf = malloc(2 * explen);
    if (buf == NULL) {
        printf("ERROR: No memory for result data\n");
        assert(0 && "No memory for result data");
    }
    buflen = 2 * explen;

    params.params_version = CSS_STYLESHEET_PARAMS_VERSION_1;
    params.level = CSS_LEVEL_21;
    params.charset = "UTF-8";
    params.url = "foo";
    params.title = NULL;
    params.allow_quirks = false;
    params.inline_style = false;
    params.resolve = resolve_url;
    params.resolve_pw = NULL;
    params.import = NULL;
    params.import_pw = NULL;
    params.color = NULL;
    params.color_pw = NULL;
    params.font = NULL;
    params.font_pw = NULL;

    error = css_stylesheet_create(&params, &sheet);
    if (error != CSS_OK) {
        printf("ERROR: css_stylesheet_create failed with error %d\n", error);
        assert(0 && "Failed to create stylesheet");
    }

    printf("DEBUG: Appending %zu bytes of data\n", len);
    error = css_stylesheet_append_data(sheet, data, len);
    if (error != CSS_OK && error != CSS_NEEDDATA) {
        printf("ERROR: Failed appending data: %d\n", error);
        assert(0);
    }

    printf("DEBUG: Finalizing stylesheet data\n");
    error = css_stylesheet_data_done(sheet);
    if (error != CSS_OK) {
        printf("ERROR: css_stylesheet_data_done failed with error %d\n", error);
        assert(0);
    }

    testnum++;

    printf("Test %d: ", testnum);

    dump_sheet(sheet, buf, &buflen);

    if (2 * explen - buflen != explen ||
            (explen > 0 && memcmp(buf, exp, explen) != 0)) {
        printf("ERROR: Result doesn't match expected\n");
        printf("Expected (%u):\n%.*s\n",
               (int) explen, (int) explen, exp);
        printf("Result (%u):\n%.*s\n", (int) (2 * explen - buflen),
               (int) (2 * explen - buflen), buf);
        assert(0 && "Result doesn't match expected");
    }

    css_stylesheet_destroy(sheet);

    free(buf);

    printf("PASS\n");
}