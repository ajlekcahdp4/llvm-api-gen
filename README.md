# llvm-api-gen

## Install dependencies

To install all needed dependencies run [nix](https://nixos.org/download/)

```sh
nix develop
```

## Build

```sh
meson setup build
meson compile -C build
```

Or using nix build:

```sh
nix build .
```

## Run

To run compiled:

```sh
opt -load-pass-plugin build/lib/libllvm-api-gen.so -passes "llvm-api-gen" build/highlife.ll --disable-output
```

Or (if you used nix build)

```sh
opt -load-pass-plugin result/lib/libllvm-api-gen.so -passes "llvm-api-gen" build/highlife.ll --disable-output
```
