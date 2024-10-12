{ pkgs, stdenv, ... }:
stdenv.mkDerivation {
  src = ./.;
  pname = "llvm-api-gen";
  version = "0.0.0";
  nativeBuildInputs = with pkgs; [
    meson
    ninja
  ];
  buildInputs = with pkgs; [ llvm_18 ];
}
