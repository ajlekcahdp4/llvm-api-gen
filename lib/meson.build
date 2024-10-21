llvm_dep = dependency('llvm')
incdir = ['../include']

llvm_api_gen_lib = library('llvm-api-gen', 'llvm-api-gen/llvm-api-gen.cpp',
  dependencies: [llvm_dep], include_directories: incdir, install: true
)
install_headers('../include/llvm-api-gen/llvm-api-gen.h',
  subdir: 'llvm-api-gen'
)
