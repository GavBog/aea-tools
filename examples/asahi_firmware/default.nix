{
  pkgs ? import <nixpkgs> { },
}:

let
  extractor = pkgs.rustPlatform.buildRustPackage {
    pname = "asahi-firmware-extractor";
    version = "0.1.0";
    src = ../../.;
    buildAndTestSubdir = "examples/asahi_firmware";
    cargoLock = {
      lockFile = ../../Cargo.lock;
      outputHashes = {
        "exhume_apfs-0.1.1" = "sha256-T5Xut8iHvyxesl7Mbqy9lEms+O9iOX5tT3CPj/2L8G4=";
      };
    };
  };
in
pkgs.stdenv.mkDerivation {
  name = "asahi-extracted-firmware";

  outputHashMode = "recursive";
  outputHashAlgo = "sha256";
  outputHash = "sha256-agR/84QvYf49Gj9RzNHOcQFsE0cDfjBKo7uS9kRp6eE=";

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
