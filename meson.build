project(
  'llvm-api-gen',
  'cpp',
  default_options: ['cpp_std=c++23', 'warning_level=3'],
)

subdir('lib')

llvm_dep = dependency('llvm')

#executable('test-generated', 'tests/generated.cpp', dependencies: [llvm_dep])
