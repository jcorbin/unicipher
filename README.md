# UniCipher 𓂀

A Zig response to and further musing inspired by <https://github.com/klnusbaum/unicipher>.

## Build / Test / Install

- you'll need the latest [zig nightly](https://ziglang.org/download/) and probably some luck
  - it won't build with zig v0.10 release
  - it may not build with a moving target once I stop developing this repo
- run tests with `zig build test`
- easy dev mode running via `zig build run-enc` and `zig build run-dec`
- or just drive `zig-out/bin/unicipher` after running `zig build`

You may also want to run something like `zig build -p $HOME/.local` to install
a copy of the `unicipher` binary into your path (presuming you've got
`$HOME/.local/bin` in `$PATH`).

## Usage

Run `unicipher -h` for full details, but a basic round-trip demo looks like:
```shell
$ echo hello | unicipher encrypt | unicpher decrypt
```

