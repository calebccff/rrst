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