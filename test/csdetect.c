#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#include <parserutils/charset/mibenum.h>

#include <libcss/libcss.h>

#include "charset/detect.h"
#include "utils/utils.h"

#include "testutils.h"

typedef struct line_ctx {
    size_t buflen;
    size_t bufused;
    uint8_t *buf;
    char enc[64];
    bool indata;
    bool encoding_pending;
} line_ctx;

static bool handle_line(const char *data, size_t datalen, void *pw);
static void run_test(const uint8_t *data, size_t len, char *expected);

int main(int argc, char **argv)
{
    line_ctx ctx;
    struct stat st;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    if (stat(argv[1], &st) != 0) {
        fprintf(stderr, "Failed to stat %s: %s\n", argv[1], strerror(errno));
        return 1;
    }
    ctx.buflen = st.st_size;
    if (ctx.buflen == 0) {
        fprintf(stderr, "File %s is empty\n", argv[1]);
        return 1;
    }

    ctx.buf = malloc(ctx.buflen);
    if (ctx.buf == NULL) {
        fprintf(stderr, "Failed allocating %u bytes for %s\n",
                (unsigned int) ctx.buflen, argv[1]);
        return 1;
    }

    ctx.buf[0] = '\0';
    ctx.enc[0] = '\0';
    ctx.bufused = 0;
    ctx.indata = true;  // Start in data mode
    ctx.encoding_pending = false;

    fprintf(stderr, "Parsing test file: %s\n", argv[1]);
    if (!css__parse_testfile(argv[1], handle_line, &ctx)) {
        fprintf(stderr, "Failed to parse test file: %s\n", argv[1]);
        free(ctx.buf);
        return 1;
    }

    /* Run final test if data is pending */
    if (ctx.bufused > 0 && ctx.enc[0] != '\0') {
        if (ctx.buf[ctx.bufused - 1] == '\n')
            ctx.bufused -= 1;

        fprintf(stderr, "Running final test case\n");
        run_test(ctx.buf, ctx.bufused, ctx.enc);
    }

    free(ctx.buf);

    fprintf(stderr, "PASS\n");
    return 0;
}

bool handle_line(const char *data, size_t datalen, void *pw)
{
    line_ctx *ctx = (line_ctx *) pw;

    fprintf(stderr, "Processing line: %.*s\n", (int)datalen, data);

    if (data[0] == '#') {
        if (ctx->encoding_pending) {
            fprintf(stderr, "Error: Missing encoding value after #encoding\n");
            return false;
        }

        if (strncasecmp(data+1, "encoding", 8) == 0) {
            /* Start of encoding section; wait for the next line */
            ctx->encoding_pending = true;
            ctx->indata = false;
        } else if (strncasecmp(data+1, "data", 4) == 0) {
            ctx->indata = true;
        }
    } else if (datalen > 1 || data[0] != '\n') {  // Ignore blank lines
        if (ctx->encoding_pending) {
            /* This is the encoding value */
            strncpy(ctx->enc, data, sizeof(ctx->enc) - 1);
            ctx->enc[sizeof(ctx->enc) - 1] = '\0';
            if (ctx->enc[strlen(ctx->enc) - 1] == '\n')
                ctx->enc[strlen(ctx->enc) - 1] = '\0';
            ctx->encoding_pending = false;

            /* Run test case now that we have data and encoding */
            if (ctx->bufused > 0) {
                if (ctx->buf[ctx->bufused - 1] == '\n')
                    ctx->bufused -= 1;

                fprintf(stderr, "Running test case: data='%.*s', encoding='%s'\n",
                        (int)ctx->bufused, ctx->buf, ctx->enc);
                run_test(ctx->buf, ctx->bufused, ctx->enc);

                ctx->buf[0] = '\0';
                ctx->enc[0] = '\0';
                ctx->bufused = 0;
            }
            ctx->indata = true;  // Resume data accumulation
        } else if (ctx->indata) {
            /* Accumulate data, including BOM */
            if (ctx->bufused + datalen <= ctx->buflen) {
                memcpy(ctx->buf + ctx->bufused, data, datalen);
                ctx->bufused += datalen;
            } else {
                fprintf(stderr, "Error: Buffer overflow for data\n");
                return false;
            }
        }
    }

    return true;
}

void run_test(const uint8_t *data, size_t len, char *expected)
{
    uint16_t mibenum = 0;
    css_charset_source source = CSS_CHARSET_DEFAULT;
    static int testnum;

    fprintf(stderr, "Test %d: Expected encoding='%s'\n", testnum + 1, expected);

    if (css__charset_extract(data, len, &mibenum, &source) != PARSERUTILS_OK) {
        fprintf(stderr, "Test %d: css__charset_extract failed\n", testnum + 1);
        exit(1);
    }

    if (mibenum == 0) {
        fprintf(stderr, "Test %d: No charset detected\n", testnum + 1);
        exit(1);
    }

    uint16_t expected_mibenum = parserutils_charset_mibenum_from_name(expected, strlen(expected));
    fprintf(stderr, "Test %d: Detected charset %s (%d), Source %d, Expected %s (%d)\n",
            ++testnum, parserutils_charset_mibenum_to_name(mibenum),
            mibenum, source, expected, expected_mibenum);

    if (mibenum != expected_mibenum) {
        fprintf(stderr, "Test %d: Mismatch: Detected %d, Expected %d\n",
                testnum, mibenum, expected_mibenum);
        exit(1);
    }
}