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
  outputHash = "sha256-VymyzKl+X80UBawd6NiFSWQXV8Q09MwOVrDpEG9RGx0=";

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
