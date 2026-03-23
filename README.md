# Apple Encrypted Archive Tools
This crate provides tools to work with Apple encrypted archives!

## Asahi Firmware
If you are here to use the asahi firmware tool with NixOS you can add the flake to your inputs

```nix
aea-tools = {
  url = "github:GavBog/aea-tools";
  inputs.nixpkgs.follows = "nixpkgs";
};
```

and then in your system configuration set

```nix
hardware.asahi.peripheralFirmwareDirectory = inputs.aea-tools.packages.aarch64-linux.default;
```

if you are extracting the firmware for another system (not NixOS) just run

```bash
cargo run -p asahi_firmware --release <output_directory>
```
