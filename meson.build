project(
  'netpanzer-masterserver',
  ['c'],
  version: '0.1.0.555',
  meson_version : '>= 0.58.0',
  default_options: [
    'warning_level=2',
    'b_sanitize=address,undefined',
    'b_lundef=false',
    ]
  )

# Setup compiler.
cc = meson.get_compiler('c')

extra_flags = [
  '-fno-common',
#  '-fstack-protector-strong',
#  '-Wformat-security',
#  '-Wformat-overflow=2',
  '-Wshadow',
#  '-Wstrict-overflow=5'
# '-Wconversion'
  ]

add_project_arguments(cc.get_supported_arguments(extra_flags), language: 'c')

conf = configuration_data()
conf.set_quoted('PACKAGE_VERSION', meson.project_version())
conf.set_quoted('NP_DATADIR', join_paths(get_option('prefix'), get_option('datadir')))
config_h = configure_file(output : 'config.h', configuration : conf)

deps = [
  dependency('libevent')
]

if host_machine.system() == 'windows'
    deps += cxx.find_library('ws2_32')
endif

exe = executable(
  meson.project_name(),
  'npms.c',
  include_directories : [
    '.'
  ],
  dependencies: [
    deps,
  ],
  install : false, install_dir : get_option('bindir')
)
