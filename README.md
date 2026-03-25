# Apple Encrypted Archive Tools
This crate provides tools to work with Apple encrypted archives!

## Streamable Read + Seek
Traditional extraction methods require decrypting and unpacking massive archives (often multiple GBs) to disk just to access a single file. `aea-tools` is built to allow you to read and seek within the archive without needing to extract the entire thing. This allows you to access files within the archive with minimal overhead and disk usage. Because it implements `std::io::Read` and `std::io::Seek`, it plugs seamlessly into existing Rust parsers, file system traversers, and archive tools.

Lets say you have a 16GB `.ipsw` (zip) file on a remote server that contains a 2GB `dmg.aea` file. You want to extract a single 3MB file from that DMG. You can use the following pipeline:

`http-range-client -> zip-rs -> aea-tools -> exhume-apfs`

Using this pipeline you can extract that 3MB file while using only 7-8MBs of bandwidth. (Tested with `appleh13camerad` extraction from an Apple IPSW file)

## Asahi Firmware Extractor
This repo includes [asahi_firmware](./examples/asahi_firmware), a tool built on top of aea-tools to extract firmware for Apple Silicon devices running Linux.

To use this with NixOS you can add the following to your flake inputs

```nix
aea-tools = {
  url = "github:GavBog/aea-tools";
  inputs.nixpkgs.follows = "nixpkgs";
};
```

And then in your system configuration set

```nix
hardware.asahi.peripheralFirmwareDirectory = inputs.aea-tools.packages.aarch64-linux.default;
```

If you are extracting the firmware for another system (not NixOS) just run

```bash
cargo run -p asahi_firmware --release <output_directory>
```

## Acknowledgements
- [The Apple Wiki](https://theapplewiki.com/) - Provided information about AEA files that made this project possible.
- [firmware-abomination](https://github.com/JJJollyjim/firmware-abomination) - Inspired this crate and planted the idea of extracting firmware files from IPSW files in my head. Unfortunately the method described in that repository no longer works as of macOS 15+ (Because of Apple Encrypted Archives).
