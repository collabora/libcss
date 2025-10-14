#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <libcss/libcss.h>

// Simplified parser struct (based on GstCssParse)
struct CssParser {
  css_stylesheet *stylesheet;
  css_select_ctx *select_ctx;
  char *current_cue_id;
  lwc_string *font_family;
  css_color color;
  css_color background_color;
  css_fixed font_size;
  css_unit font_size_unit;
  int video_width;
  int video_height;
};


// Stub resolution functions
static css_error resolve_url(void *pw, const char *base, lwc_string *rel, lwc_string **abs) {
  return CSS_INVALID;
}

static css_error resolve_color(void *pw, lwc_string *name, css_color *color) {
  *color = 0;
  return CSS_OK;
}

static css_error resolve_font(void *pw, lwc_string *name, css_system_font *system_font) {
  return CSS_INVALID;
}

// Minimal select handler (based on gstcssparse.c)
static css_error node_name(void *pw, void *node, css_qname *qname) {
  lwc_string *node_name = (lwc_string *)node;
  qname->name = lwc_string_ref(node_name);
  return CSS_OK;
}

static css_error node_classes(void *pw, void *node, lwc_string ***classes, uint32_t *n_classes) {
  lwc_string *node_name = (lwc_string *)node;
  const char *node_data = lwc_string_data(node_name);
  if (strncmp(node_data, "class:", 6) == 0) {
    const char *class_name = node_data + 6;
    *classes = (lwc_string **)malloc(sizeof(lwc_string *));
    lwc_intern_string(class_name, strlen(class_name), &(*classes)[0]);
    *n_classes = 1;
  } else {
    *classes = NULL;
    *n_classes = 0;
  }
  return CSS_OK;
}

static css_error node_has_name(void *pw, void *node, const css_qname *qname, bool *match) {
  lwc_string *node_name = (lwc_string *)node;
  const char *node_data = lwc_string_data(node_name);
  const char *tag_name = strncmp(node_data, "class:", 6) == 0 ? "cue" : node_data;
  lwc_string *tag_string;
  lwc_error err = lwc_intern_string(tag_name, strlen(tag_name), &tag_string);
  if (err != lwc_error_ok) {
    *match = false;
    return CSS_OK;
  }
  lwc_string_caseless_isequal(qname->name, tag_string, match);
  lwc_string_unref(tag_string);
  return CSS_OK;
}

static css_error node_has_class(void *pw, void *node, lwc_string *clz, bool *match) {
  lwc_string *node_name = (lwc_string *)node;
  const char *node_data = lwc_string_data(node_name);
  if (strncmp(node_data, "class:", 6) == 0) {
    const char *class_name = node_data + 6;
    lwc_string *class_string;
    lwc_error err = lwc_intern_string(class_name, strlen(class_name), &class_string);
    if (err != lwc_error_ok) {
      *match = false;
      return CSS_OK;
    }
    lwc_string_caseless_isequal(clz, class_string, match);
    lwc_string_unref(class_string);
  } else {
    *match = false;
  }
  return CSS_OK;
}

static css_error node_has_id(void *pw, void *node, lwc_string *id, bool *match) {
  CssParser *parser = (CssParser *)pw;
  if (!parser->current_cue_id) {
    *match = false;
    return CSS_OK;
  }
  const char *selector_id = lwc_string_data(id);
  if (selector_id[0] == '#') selector_id++;
  lwc_string *cue_id_str, *current_cue_id_str;
  lwc_error err = lwc_intern_string(selector_id, strlen(selector_id), &cue_id_str);
  if (err != lwc_error_ok) {
    *match = false;
    return CSS_OK;
  }
  err = lwc_intern_string(parser->current_cue_id, strlen(parser->current_cue_id), &current_cue_id_str);
  if (err != lwc_error_ok) {
    lwc_string_unref(cue_id_str);
    *match = false;
    return CSS_OK;
  }
  lwc_string_caseless_isequal(cue_id_str, current_cue_id_str, match);
  lwc_string_unref(cue_id_str);
  lwc_string_unref(current_cue_id_str);
  return CSS_OK;
}

static css_error node_id(void *pw, void *node, lwc_string **id) {
  CssParser *parser = (CssParser *)pw;
  if (parser->current_cue_id) {
    lwc_intern_string(parser->current_cue_id, strlen(parser->current_cue_id), id);
  } else {
    *id = NULL;
  }
  return CSS_OK;
}

static css_select_handler select_handler = {
  .handler_version = CSS_SELECT_HANDLER_VERSION_1,
  .node_name = node_name,
  .node_classes = node_classes,
  .node_has_name = node_has_name,
  .node_has_class = node_has_class,
  .node_has_id = node_has_id,
  .node_id = node_id,
  .named_ancestor_node = [](void*, void*, const css_qname*, void**)->css_error { return CSS_OK; },
  .named_parent_node = [](void*, void*, const css_qname*, void**)->css_error { return CSS_OK; },
  .named_sibling_node = [](void*, void*, const css_qname*, void**)->css_error { return CSS_OK; },
  .named_generic_sibling_node = [](void*, void*, const css_qname*, void**)->css_error { return CSS_OK; },
  .parent_node = [](void*, void*, void**)->css_error { return CSS_OK; },
  .sibling_node = [](void*, void*, void**)->css_error { return CSS_OK; },
  .node_has_attribute = [](void*, void*, const css_qname*, bool*)->css_error { return CSS_OK; },
  .node_has_attribute_equal = [](void*, void*, const css_qname*, lwc_string*, bool*)->css_error { return CSS_OK; },
  .node_has_attribute_dashmatch = [](void*, void*, const css_qname*, lwc_string*, bool*)->css_error { return CSS_OK; },
  .node_has_attribute_includes = [](void*, void*, const css_qname*, lwc_string*, bool*)->css_error { return CSS_OK; },
  .node_has_attribute_prefix = [](void*, void*, const css_qname*, lwc_string*, bool*)->css_error { return CSS_OK; },
  .node_has_attribute_suffix = [](void*, void*, const css_qname*, lwc_string*, bool*)->css_error { return CSS_OK; },
  .node_has_attribute_substring = [](void*, void*, const css_qname*, lwc_string*, bool*)->css_error { return CSS_OK; },
  .node_is_root = [](void*, void*, bool* match)->css_error { *match = true; return CSS_OK; },
  .node_count_siblings = [](void*, void*, bool, bool, int32_t* count)->css_error { *count = 0; return CSS_OK; },
  .node_is_empty = [](void*, void*, bool* match)->css_error { *match = false; return CSS_OK; },
  .node_is_link = [](void*, void*, bool* match)->css_error { *match = false; return CSS_OK; },
  .node_is_visited = [](void*, void*, bool* match)->css_error { *match = false; return CSS_OK; },
  .node_is_hover = [](void*, void*, bool* match)->css_error { *match = false; return CSS_OK; },
  .node_is_active = [](void*, void*, bool* match)->css_error { *match = false; return CSS_OK; },
  .node_is_focus = [](void*, void*, bool* match)->css_error { *match = false; return CSS_OK; },
  .node_is_enabled = [](void*, void*, bool* match)->css_error { *match = true; return CSS_OK; },
  .node_is_disabled = [](void*, void*, bool* match)->css_error { *match = false; return CSS_OK; },
  .node_is_checked = [](void*, void*, bool* match)->css_error { *match = false; return CSS_OK; },
  .node_is_target = [](void*, void*, bool* match)->css_error { *match = false; return CSS_OK; },
  .node_is_lang = [](void*, void*, lwc_string*, bool* match)->css_error { *match = false; return CSS_OK; },
  .node_presentational_hint = [](void*, void*, uint32_t* n_hints, css_hint** hints)->css_error { *n_hints = 0; *hints = NULL; return CSS_OK; },
  .ua_default_for_property = [](void*, uint32_t property, css_hint* hint)->css_error {
    if (property == CSS_PROP_COLOR) {
      hint->data.color = 0x00000000;
      hint->status = CSS_COLOR_COLOR;
    } else if (property == CSS_PROP_FONT_FAMILY) {
      hint->data.strings = NULL;
      hint->status = CSS_FONT_FAMILY_SANS_SERIF;
    } else {
      return CSS_INVALID;
    }
    return CSS_OK;
  },
  .set_libcss_node_data = [](void*, void*, void*)->css_error { return CSS_OK; },
  .get_libcss_node_data = [](void*, void*, void**)->css_error { return CSS_OK; }
};

// Simplified string replace (from replace_string)
static char* replace_string(const char *input, const char *find, const char *replace) {
  size_t find_len = strlen(find);
  size_t replace_len = strlen(replace);
  size_t input_len = strlen(input);
  size_t count = 0;
  const char *ptr = input;
  while ((ptr = strstr(ptr, find))) {
    count++;
    ptr += find_len;
  }
  size_t new_len = input_len + count * (replace_len - find_len);
  char *result = (char *)malloc(new_len + 1);
  char *dest = result;
  ptr = input;
  while (const char *next = strstr(ptr, find)) {
    size_t len = next - ptr;
    memcpy(dest, ptr, len);
    dest += len;
    memcpy(dest, replace, replace_len);
    dest += replace_len;
    ptr = next + find_len;
  }
  strcpy(dest, ptr);
  return result;
}

// Initialize parser
static void init_parser(CssParser *parser) {
  css_stylesheet_params params = {
    .params_version = CSS_STYLESHEET_PARAMS_VERSION_1,
    .level = CSS_LEVEL_3,
    .charset = "UTF-8",
    .url = "webvtt://localhost",
    .allow_quirks = false,
    .inline_style = false,
    .resolve = resolve_url,
    .resolve_pw = NULL,
    .color = resolve_color,
    .color_pw = NULL,
    .font = resolve_font,
    .font_pw = NULL
  };
  css_stylesheet_create(&params, &parser->stylesheet);
  css_select_ctx_create(&parser->select_ctx);
  css_select_ctx_append_sheet(parser->select_ctx, parser->stylesheet, CSS_ORIGIN_AUTHOR, NULL);
  parser->current_cue_id = NULL;
  parser->font_family = NULL;
  parser->color = 0;
  parser->background_color = 0;
  parser->font_size = 0;
  parser->font_size_unit = CSS_UNIT_PX;
  parser->video_width = 1920;
  parser->video_height = 1080;
}

// Free parser
static void free_parser(CssParser *parser) {
  if (parser->stylesheet) css_stylesheet_destroy(parser->stylesheet);
  if (parser->select_ctx) css_select_ctx_destroy(parser->select_ctx);
  free(parser->current_cue_id);
  if (parser->font_family) lwc_string_unref(parser->font_family);
}

// Parse CSS (adapted from gst_cssparse_parse)
static css_error parse_css(CssParser *parser, const char *css_data) {
  if (!parser->stylesheet || !parser->select_ctx) return CSS_INVALID;
  if (!css_data || !css_data[0]) return CSS_OK;

  // Preprocess CSS
  char *processed_css;
  if (strstr(css_data, "::cue") || strstr(css_data, "\\(#")) {
    processed_css = replace_string(css_data, "::cue", "cue");
    char *temp_css = processed_css;
    processed_css = replace_string(temp_css, "\\(#", "#");
    free(temp_css);
  } else {
    processed_css = strdup(css_data);
  }

  // Append CSS to stylesheet
  css_error code = css_stylesheet_append_data(parser->stylesheet, (const uint8_t *)processed_css, strlen(processed_css));
  free(processed_css);
  if (code == CSS_OK || code == CSS_NEEDDATA) {
    code = css_stylesheet_data_done(parser->stylesheet);
  }
  if (code != CSS_OK) return code;

  // Select style
  css_unit_ctx unit_ctx = { .viewport_width = parser->video_width, .viewport_height = parser->video_height };
  lwc_string *node_name;
  lwc_intern_string("cue", 3, &node_name);
  css_media media = { .type = CSS_MEDIA_SCREEN };
  css_select_results *results;
  code = css_select_style(parser->select_ctx, node_name, &unit_ctx, &media, NULL, &select_handler, parser, &results);
  if (code == CSS_OK && results->styles[CSS_PSEUDO_ELEMENT_NONE]) {
    css_computed_style *style = results->styles[CSS_PSEUDO_ELEMENT_NONE];
    css_fixed font_size;
    css_unit font_size_unit;
    if (css_computed_font_size(style, &font_size, &font_size_unit) == CSS_FONT_SIZE_DIMENSION && font_size > 0) {
      parser->font_size = font_size;
      parser->font_size_unit = font_size_unit;
    }
    css_color color;
    if (css_computed_color(style, &color) == CSS_COLOR_COLOR) parser->color = color;
    css_color bg_color;
    if (css_computed_background_color(style, &bg_color) == CSS_BACKGROUND_COLOR_COLOR) parser->background_color = bg_color;
    lwc_string **font_families;
    if (css_computed_font_family(style, &font_families) && font_families && font_families[0]) {
      parser->font_family = lwc_string_ref(font_families[0]);
    }
    css_select_results_destroy(results);
  }
  lwc_string_unref(node_name);
  return code;
}

// Static initializer
struct Initializer {
  Initializer() {
    // No specific initialization needed for libcss
  }
};

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
  static Initializer init;
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* buf, size_t len) {
  // Skip empty or overly large inputs
  if (len < 1 || len > 1024 * 1024) return 0;

  // Initialize parser
  CssParser *parser = (CssParser *)calloc(1, sizeof(CssParser));
  init_parser(parser);

  // Set cue ID from input
  char cue_id[128];
  size_t cue_len = len < 127 ? len : 127;
  memcpy(cue_id, buf, cue_len);
  cue_id[cue_len] = '\0';
  for (size_t i = 0; i < cue_len; i++) {
    if (cue_id[i] < 32 || cue_id[i] > 126) cue_id[i] = 'a';
  }
  parser->current_cue_id = strdup(cue_id);

  // Create null-terminated CSS input
  char *css_input = (char *)malloc(len + 1);
  memcpy(css_input, buf, len);
  css_input[len] = '\0';

  // Fuzz the CSS parser
  parse_css(parser, css_input);

  // Cleanup
  free(css_input);
  free_parser(parser);
  free(parser);

  return 0;
}
