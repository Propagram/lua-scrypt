# lua-scrypt
Pure Lua Scrypt KDF

*Scrypt is a KDF (Key Derivation Function) designed for password storage by Colin Percival to be resistant against hardware-assisted attackers by having a tunable memory cost. It is described in RFC 7914.*

This module was inspired by https://github.com/cryptocoinjs/scryptsy

## Requirements

### [Lua-Lockbox](https://github.com/somesocks/lua-lockbox)
*A collection of cryptographic primitives and protocols written in pure Lua. This was written to provide cross-platform, tested reference implementations of many different cryptographic primitives. These are written to be easy to read and easy to use, not for performance!*

Install via [Luarocks](https://luarocks.org):
```
luarocks instal lockbox
```
Or download and extract it.

## TODO

 - Deploy to LuaRocks
 - Add tests
 - Add (if available) Luajit FFI to avoid memory dump

## License

MIT License

Copyright (c) 2023 Propagram

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
