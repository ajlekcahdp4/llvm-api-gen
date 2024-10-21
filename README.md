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

## Run

```sh
opt -load-pass-plugin build/lib/libllvm-api-gen.so -passes "llvm-api-gen" build/highlife.ll --disable-output
```
