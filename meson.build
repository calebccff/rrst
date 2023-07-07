project('rrst', 'c')

deps = [
    dependency('threads'),
    dependency('libudev'),
]

src = [
    'rrst.c',
    'ttypersist.c',
]

executable('rrst', src,
    include_directories: ['.'],
    dependencies: deps,
    install: true)

install_data('rrst.service', rename: '/usr/lib/systemd/user/rrst.service')
