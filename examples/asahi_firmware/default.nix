{
  pkgs ? import <nixpkgs> { },
}:

let
  extractor = pkgs.rustPlatform.buildRustPackage {
    pname = "asahi-firmware-extractor";
    version = "0.1.0";
    src = ../../.;
    buildAndTestSubdir = "examples/asahi_firmware";
    cargoLock.lockFile = ../../Cargo.lock;
  };
in
pkgs.stdenv.mkDerivation {
  name = "asahi-extracted-firmware";

  outputHashMode = "recursive";
  outputHashAlgo = "sha256";
  outputHash = "sha256-3s0K9eUb4OqzWYIii1DV6DMhrhFQp68902bQCbvQ85c=";

  nativeBuildInputs = [
    extractor
    pkgs.cacert
  ];

  SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";

  phases = [ "installPhase" ];
  installPhase = ''
    mkdir -p $out
    ${extractor}/bin/asahi_firmware "$out"
  '';
}
