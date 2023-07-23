project('rrst', ['c', 'rust'], version: '0.1')

# OLD rust interop
# Run cbindgen to generate the header file
# cbindgen = find_program('cbindgen', required: true)

# srcdir = meson.current_source_dir()
# cbindgen_config = join_paths(srcdir, 'cbindgen.toml')
# pts_api_headers = custom_target('pts_api_headers', output: ['pts_api.h'],
#     command: [cbindgen, '--config', cbindgen_config, '--crate', 'pts', '--output', '@OUTPUT@', srcdir],
#     build_always: true)

# pts_api_src = [
#     'pts.rs',
# ]

# pts_api_lib = static_library('pts', pts_api_src, install: false, rust_crate_type: 'staticlib')

# Rust interop via cargo
cargo = find_program('cargo', required : true)
if get_option('buildtype') == 'release'
    cargo_args = ['--release']
    target_dir = 'release'
else
    cargo_args = []
    target_dir = 'debug'
endif
env = environment()
srcdir = meson.current_source_dir()
builddir = meson.current_build_dir()
message('builddir: ' + builddir)
env.set('CARGO_TARGET_DIR', builddir)
cargo_result = run_command('cargo', ['build', '--manifest-path', join_paths(srcdir, 'Cargo.toml')] + cargo_args, check: true, env: env)
cargo_stdout = cargo_result.stdout().strip()
cargo_stderr = cargo_result.stderr().strip()
if cargo_stderr != ''
    message(cargo_stderr)
elif cargo_stdout != ''
    message(cargo_stdout)
else
    message('Cargo build succeeded')
endif

grab_objects = find_program('find_rust_libs.sh')
cargo_rslib_objects = run_command(grab_objects, [join_paths(builddir, target_dir)], check: true).stdout().strip().split('\n')

message('Found objects:')
message(cargo_rslib_objects)

deps = [
    dependency('threads'),
    dependency('libudev'),
    dependency('inih'),
]

src = [
    'rrst.c',
    'ttypersist.c',
    'config.c',
    'control_rtsdtr.c',
    'control_qcomdbg.c',
]

executable('rrst', src,
    include_directories: ['.'],
    dependencies: deps,
    link_with: library('pts_api', 'pts.rs'),
    objects : cargo_rslib_objects,
    install: true)

install_data('rrst.service', rename: '/usr/lib/systemd/user/rrst.service')

meson.add_install_script('install.sh')
