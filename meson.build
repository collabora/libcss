project('libcss', 'c',
  version: '0.9.2',
  default_options: ['c_std=c99', 'warning_level=2'])

cc = meson.get_compiler('c')

# Compiler flags
cflags = ['-D_BSD_SOURCE', '-D_DEFAULT_SOURCE', '-DSTMTEXPR']
if cc.get_id() != 'gcc' or cc.version().split('.')[0].to_int() >= 3
  cflags += ['-Wstrict-prototypes', '-Wmissing-prototypes', '-Wmissing-declarations', '-Wnested-externs']
endif

# Relaxed flags for libcss_relaxed
libcss_relaxed_cflags = ['-D_BSD_SOURCE', '-D_DEFAULT_SOURCE', '-pedantic']

# Dependencies
wapcaplet_dep = dependency('libwapcaplet', version: '>=0.4.3', required: false, fallback: ['libwapcaplet', 'wapcaplet_dep'])
parserutils_dep = dependency('libparserutils', version: '>=0.2.5', required: false, fallback: ['libparserutils', 'parserutils_dep'])

if not wapcaplet_dep.found() or not parserutils_dep.found()
  error('libwapcaplet and libparserutils are required')
endif

# Find programs
python = find_program('python3', required: false)
cc_prog = find_program('cc')

# Source files
libcss_sources = files(
  'src/charset/detect.c',
  'src/lex/lex.c',
  'src/parse/font_face.c',
  'src/parse/important.c',
  'src/parse/language.c',
  'src/parse/mq.c',
  'src/parse/parse.c',
  'src/parse/propstrings.c',
  'src/parse/properties/azimuth.c',
  'src/parse/properties/background.c',
  'src/parse/properties/background_position.c',
  'src/parse/properties/border.c',
  'src/parse/properties/border_color.c',
  'src/parse/properties/border_spacing.c',
  'src/parse/properties/border_style.c',
  'src/parse/properties/border_width.c',
  'src/parse/properties/clip.c',
  'src/parse/properties/column_rule.c',
  'src/parse/properties/columns.c',
  'src/parse/properties/content.c',
  'src/parse/properties/cue.c',
  'src/parse/properties/cursor.c',
  'src/parse/properties/elevation.c',
  'src/parse/properties/fill_opacity.c',
  'src/parse/properties/flex.c',
  'src/parse/properties/flex_flow.c',
  'src/parse/properties/font.c',
  'src/parse/properties/font_family.c',
  'src/parse/properties/font_weight.c',
  'src/parse/properties/list_style.c',
  'src/parse/properties/list_style_type.c',
  'src/parse/properties/margin.c',
  'src/parse/properties/opacity.c',
  'src/parse/properties/outline.c',
  'src/parse/properties/overflow.c',
  'src/parse/properties/padding.c',
  'src/parse/properties/pause.c',
  'src/parse/properties/play_during.c',
  'src/parse/properties/properties.c',
  'src/parse/properties/quotes.c',
  'src/parse/properties/stroke_opacity.c',
  'src/parse/properties/text_decoration.c',
  'src/parse/properties/utils.c',
  'src/parse/properties/voice_family.c',
  'src/select/arena.c',
  'src/select/calc.c',
  'src/select/computed.c',
  'src/select/dispatch.c',
  'src/select/font_face.c',
  'src/select/format_list_style.c',
  'src/select/hash.c',
  'src/select/select.c',
  'src/select/strings.c',
  'src/select/unit.c',
  'src/select/properties/align_content.c',
  'src/select/properties/align_items.c',
  'src/select/properties/align_self.c',
  'src/select/properties/azimuth.c',
  'src/select/properties/background_attachment.c',
  'src/select/properties/background_color.c',
  'src/select/properties/background_image.c',
  'src/select/properties/background_position.c',
  'src/select/properties/background_repeat.c',
  'src/select/properties/border_bottom_color.c',
  'src/select/properties/border_bottom_style.c',
  'src/select/properties/border_bottom_width.c',
  'src/select/properties/border_collapse.c',
  'src/select/properties/border_left_color.c',
  'src/select/properties/border_left_style.c',
  'src/select/properties/border_left_width.c',
  'src/select/properties/border_right_color.c',
  'src/select/properties/border_right_style.c',
  'src/select/properties/border_right_width.c',
  'src/select/properties/border_spacing.c',
  'src/select/properties/border_top_color.c',
  'src/select/properties/border_top_style.c',
  'src/select/properties/border_top_width.c',
  'src/select/properties/bottom.c',
  'src/select/properties/box_sizing.c',
  'src/select/properties/break_after.c',
  'src/select/properties/break_before.c',
  'src/select/properties/break_inside.c',
  'src/select/properties/caption_side.c',
  'src/select/properties/clear.c',
  'src/select/properties/clip.c',
  'src/select/properties/color.c',
  'src/select/properties/column_count.c',
  'src/select/properties/column_fill.c',
  'src/select/properties/column_gap.c',
  'src/select/properties/column_rule_color.c',
  'src/select/properties/column_rule_style.c',
  'src/select/properties/column_rule_width.c',
  'src/select/properties/column_span.c',
  'src/select/properties/column_width.c',
  'src/select/properties/content.c',
  'src/select/properties/counter_increment.c',
  'src/select/properties/counter_reset.c',
  'src/select/properties/cue_after.c',
  'src/select/properties/cue_before.c',
  'src/select/properties/cursor.c',
  'src/select/properties/direction.c',
  'src/select/properties/display.c',
  'src/select/properties/elevation.c',
  'src/select/properties/empty_cells.c',
  'src/select/properties/fill_opacity.c',
  'src/select/properties/flex_basis.c',
  'src/select/properties/flex_direction.c',
  'src/select/properties/flex_grow.c',
  'src/select/properties/flex_shrink.c',
  'src/select/properties/flex_wrap.c',
  'src/select/properties/float.c',
  'src/select/properties/font_family.c',
  'src/select/properties/font_size.c',
  'src/select/properties/font_style.c',
  'src/select/properties/font_variant.c',
  'src/select/properties/font_weight.c',
  'src/select/properties/height.c',
  'src/select/properties/helpers.c',
  'src/select/properties/justify_content.c',
  'src/select/properties/left.c',
  'src/select/properties/letter_spacing.c',
  'src/select/properties/line_height.c',
  'src/select/properties/list_style_image.c',
  'src/select/properties/list_style_position.c',
  'src/select/properties/list_style_type.c',
  'src/select/properties/margin_bottom.c',
  'src/select/properties/margin_left.c',
  'src/select/properties/margin_right.c',
  'src/select/properties/margin_top.c',
  'src/select/properties/max_height.c',
  'src/select/properties/max_width.c',
  'src/select/properties/min_height.c',
  'src/select/properties/min_width.c',
  'src/select/properties/opacity.c',
  'src/select/properties/order.c',
  'src/select/properties/orphans.c',
  'src/select/properties/outline_color.c',
  'src/select/properties/outline_style.c',
  'src/select/properties/outline_width.c',
  'src/select/properties/overflow_x.c',
  'src/select/properties/overflow_y.c',
  'src/select/properties/padding_bottom.c',
  'src/select/properties/padding_left.c',
  'src/select/properties/padding_right.c',
  'src/select/properties/padding_top.c',
  'src/select/properties/page_break_after.c',
  'src/select/properties/page_break_before.c',
  'src/select/properties/page_break_inside.c',
  'src/select/properties/pause_after.c',
  'src/select/properties/pause_before.c',
  'src/select/properties/pitch.c',
  'src/select/properties/pitch_range.c',
  'src/select/properties/play_during.c',
  'src/select/properties/position.c',
  'src/select/properties/quotes.c',
  'src/select/properties/richness.c',
  'src/select/properties/right.c',
  'src/select/properties/speak.c',
  'src/select/properties/speak_header.c',
  'src/select/properties/speak_numeral.c',
  'src/select/properties/speak_punctuation.c',
  'src/select/properties/speech_rate.c',
  'src/select/properties/stress.c',
  'src/select/properties/stroke_opacity.c',
  'src/select/properties/table_layout.c',
  'src/select/properties/text_align.c',
  'src/select/properties/text_decoration.c',
  'src/select/properties/text_indent.c',
  'src/select/properties/text_transform.c',
  'src/select/properties/top.c',
  'src/select/properties/unicode_bidi.c',
  'src/select/properties/vertical_align.c',
  'src/select/properties/visibility.c',
  'src/select/properties/voice_family.c',
  'src/select/properties/volume.c',
  'src/select/properties/white_space.c',
  'src/select/properties/widows.c',
  'src/select/properties/width.c',
  'src/select/properties/word_spacing.c',
  'src/select/properties/writing_mode.c',
  'src/select/properties/z_index.c',
  'src/stylesheet.c',
  'src/utils/errors.c',
  'src/utils/utils.c'
)

# Include directories
inc = include_directories('include', 'src')

# Generated files for select
if python.found()
  gen_files = custom_target('select_gen',
    output: ['autogenerated_computed.h', 'autogenerated_destroy.inc', 'autogenerated_propget.h', 'autogenerated_propset.h'],
    input: 'src/select/select_generator.py',
    command: [python, '@INPUT@', meson.project_build_root()],
    depend_files: ['src/select/assets.py', 'src/select/overrides.py'],
    build_by_default: true
  )
  libcss_sources += gen_files
endif

# Build css_property_parser_gen
css_property_parser_gen = executable('css_property_parser_gen',
  sources: 'src/parse/properties/css_property_parser_gen.c',
  c_args: cflags,
  install: false
)

# List properties from properties.gen
properties = [
  'background_repeat', 'border_collapse', 'cue_after', 'cue_before', 'direction',
  'display', 'empty_cells', 'float', 'font_size', 'font_style', 'font_variant',
  'height', 'letter_spacing', 'line_height', 'border_top', 'border_bottom',
  'border_left', 'border_right', 'max_height', 'max_width', 'min_height',
  'min_width', 'color', 'padding_side', 'padding_bottom', 'padding_left',
  'padding_top', 'padding_right', 'margin_side', 'margin_top', 'margin_bottom',
  'margin_left', 'margin_right', 'side', 'top', 'bottom', 'left', 'right',
  'border_side_width', 'border_top_width', 'border_bottom_width',
  'border_left_width', 'border_right_width', 'border_side_style',
  'border_top_style', 'border_bottom_style', 'border_left_style',
  'border_right_style', 'border_side_color', 'border_top_color',
  'border_bottom_color', 'border_left_color', 'border_right_color',
  'counter_increment', 'counter_reset', 'background_attachment',
  'background_color', 'caption_side', 'clear', 'background_image',
  'list_style_image', 'list_style_position', 'orphans', 'outline_color',
  'outline_style', 'outline_width', 'overflow_x', 'overflow_y',
  'page_break_after', 'page_break_before', 'page_break_inside', 'pause_after',
  'pause_before', 'pitch', 'pitch_range', 'position', 'richness', 'speak',
  'speak_header', 'speak_numeral', 'speak_punctuation', 'speech_rate', 'stress',
  'table_layout', 'text_align', 'text_indent', 'text_transform', 'unicode_bidi',
  'vertical_align', 'visibility', 'volume', 'white_space', 'widows', 'width',
  'word_spacing', 'z_index', 'break_after', 'break_before', 'break_inside',
  'column_count', 'column_fill', 'column_gap', 'column_rule_color',
  'column_rule_style', 'column_rule_width', 'column_span', 'column_width',
  'writing_mode', 'box_sizing', 'align_content', 'align_items', 'align_self',
  'flex_basis', 'flex_direction', 'flex_grow', 'flex_shrink', 'flex_wrap',
  'justify_content', 'order'
]

# Generate autogenerated_<property>.c for each property
autogen_sources = []
foreach prop : properties
  descriptor_file = custom_target('descriptor_' + prop,
    output: ['descriptor_@0@.txt'.format(prop)],
    input: ['src/parse/properties/properties.gen', 'src/parse/properties/extract_prop.py'],
    command: ['sh', '-c', python.full_path() + ' $0 $1 ' + '@0@'.format(prop) + ' > $2 || { echo "Error: Failed to generate descriptor for ' + prop + '"; exit 1; }', '@INPUT1@', '@INPUT0@', '@OUTPUT@'],
    build_by_default: true
  )
  autogen_sources += custom_target('autogen_' + prop,
    output: ['autogenerated_@0@.c'.format(prop)],
    input: descriptor_file,
    command: ['sh', '-c', css_property_parser_gen.full_path() + ' -o "$1" "$(cat "$0")" || { echo "Error: Failed to generate autogen for ' + prop + '"; exit 1; }', '@INPUT@', '@OUTPUT@'],
    depends: [css_property_parser_gen, descriptor_file],
    depend_files: ['src/parse/properties/properties.gen'],
    build_by_default: true
  )
endforeach

# Include autogen sources in libcss
libcss_sources += autogen_sources

# Build the static library
libcss_lib = static_library('libcss',
  sources: libcss_sources,
  include_directories: inc,
  c_args: cflags,
  dependencies: [parserutils_dep, wapcaplet_dep],
  install: true
)

# Build the relaxed library
libcss_relaxed_lib = static_library('libcss_relaxed',
  sources: ['src/parse/properties/css_property_parser_gen.c'],
  include_directories: inc,
  c_args: libcss_relaxed_cflags,
  dependencies: [parserutils_dep, wapcaplet_dep],
  install: true
)

# Install headers
install_headers(
  'include/libcss/computed.h',
  'include/libcss/errors.h',
  'include/libcss/font_face.h',
  'include/libcss/fpmath.h',
  'include/libcss/functypes.h',
  'include/libcss/hint.h',
  'include/libcss/libcss.h',
  'include/libcss/properties.h',
  'include/libcss/select.h',
  'include/libcss/stylesheet.h',
  'include/libcss/types.h',
  'include/libcss/unit.h',
  subdir: 'libcss'
)

# Pkg-config file
pkg = import('pkgconfig')
pkg.generate(libcss_lib,
  name: 'libcss',
  description: 'CSS parsing and selection library',
  version: '0.9.2',
  subdirs: 'libcss',
  libraries: [parserutils_dep, wapcaplet_dep]
)

# Define libcss_dep for use by other subprojects
libcss_dep = declare_dependency(
  link_with: [libcss_lib],  # Link with the static library
  include_directories: inc,  # Include directories for libcss headers
  dependencies: [wapcaplet_dep, parserutils_dep]  # Transitive dependencies
)

# Tests
if get_option('tests')
  test_sources = [
    'test/csdetect.c',
    #'test/css21.c',  # Commented out in original
    'test/lex.c',
    'test/lex-auto.c',
    'test/number.c',
    'test/parse.c',
    'test/parse-auto.c',
    'test/parse2-auto.c',
    'test/select.c',
    'test/testutils.c'
  ]

  # Map test names to data files
  test_data_files = {
    'csdetect': 'data/csdetect/bom-charset-with-bom.dat',
    'lex': 'data/lex/tests1.dat',
    'lex-auto': 'data/lex/tests1.dat',
    'number': 'data/number/number.dat',
    'parse': 'data/parse/properties.dat',
    'parse-auto': 'data/parse/properties.dat',
    'parse2-auto': 'data/parse2/tests1.dat',
    'select': 'data/select/tests1.dat',
    'select2': 'data/select2/calc.dat',
    'testutils': 'data/parse/properties.dat'  # Adjust if needed
  }

  foreach src : test_sources
    test_name = src.split('/')[-1].replace('.c', '')
    test_exe_sources = [src]
    if src != 'test/testutils.c'  # Avoid linking testutils.c with itself
      test_exe_sources += ['test/testutils.c']
    endif
    test_exe = executable('css_test_' + test_name,
      sources: test_exe_sources,
      include_directories: inc,
      link_with: [libcss_lib, libcss_relaxed_lib],
      dependencies: [parserutils_dep, wapcaplet_dep],
      c_args: cflags,
      install: false
    )
    test_data_file = test_data_files.get(test_name, '')
    if test_data_file != ''
      test('css_test_' + test_name, test_exe,
        args: [meson.project_source_root() + '/test/' + test_data_file],
        workdir: meson.project_source_root() + '/test'
      )
    else
      test('css_test_' + test_name, test_exe,
        workdir: meson.project_source_root() + '/test'
      )
    endif
  endforeach
endif