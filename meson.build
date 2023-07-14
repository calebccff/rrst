project('rrst', 'c')

deps = [
    dependency('threads'),
    dependency('libudev'),
    dependency('inih')
]

src = [
    'rrst.c',
    'ttypersist.c',
    'config.c',
    'control_rtsdtr.c',
    'control_qcomdbg.c'
]

executable('rrst', src,
    include_directories: ['.'],
    dependencies: deps,
    install: true)

install_data('rrst.service', rename: '/usr/lib/systemd/user/rrst.service')

meson.add_install_script('install.sh')
