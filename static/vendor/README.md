# vendor/ — third-party code, pinned and served from this origin

Previously the page loaded these from cdnjs, unpkg and esm.sh on every start.
Whoever controls (or compromises, or MITMs) one of those hosts could run code
in the page that holds the identity keys. They are now local files, and
index.html's Content-Security-Policy no longer allows any other script origin.

| file | what | version | source | license |
|---|---|---|---|---|
| `qrcode.min.js` | QR code generator (`QRCode`) | davidshimjs/qrcodejs 1.0.0 | `raw.githubusercontent.com/davidshimjs/qrcodejs/master/qrcode.min.js` — its sha512 below equals the SRI hash I remember cdnjs publishing for 1.0.0, so it should be the same file the page loaded before — cdnjs itself was not reachable to compare directly, so diff it against the old CDN copy if you want certainty | MIT |
| `html5-qrcode.min.js` | QR scanner (`Html5Qrcode`) | html5-qrcode 2.3.8 | npm package, same file unpkg served | Apache-2.0 |
| `noble-ed25519.js` | `window.ed25519`, `window.x25519` | @noble/curves 1.4.0 (+ @noble/hashes 1.4.0, pinned by curves) | built from npm, see below | MIT |
| `noble-mlkem.js` | ML-KEM-768/1024: `window.mlkem = { ml_kem768, ml_kem1024 }` | @noble/post-quantum 0.7.1 (ml-kem only; + @noble/hashes 2.4.0, @noble/curves 2.4.0, @noble/ciphers 2.4.0) | built from npm, see below | MIT |
| `noble-argon2.js` | Argon2id, pure JS (fallback): `window.nobleArgon2 = { argon2id, argon2idAsync }` | @noble/hashes 2.4.0 (argon2 only) | built from npm, see below | MIT |
| `hash-wasm-argon2.min.js` | Argon2id, WebAssembly (primary): `window.hashwasm.argon2id` | hash-wasm 4.13.0 | npm package, unmodified `dist/argon2.umd.min.js` | MIT |

The three newer files are not referenced by index.html yet.

Argon2id backends: WASM (`hash-wasm-argon2.min.js`) first, pure JS
(`noble-argon2.js`) only when WebAssembly is unavailable. Measured on an older
phone at 512 MiB, t=3, p=2: WASM 3 s, JS 18.5 s. The WASM module is compiled by
the browser, which needs `'wasm-unsafe-eval'` in `script-src` (see CSP below).
Both backends return identical bytes (checked at 64, 256 and 512 MiB). For the JS
path use `argon2idAsync` with `asyncTick: 10` so the page stays responsive (about
5% slower than the blocking call) and `onProgress` for a progress bar; the WASM
call is one blocking call without progress, so run both in a Worker.

## CSP

`script-src 'self' 'wasm-unsafe-eval'` once the WASM file is wired in. The keyword
only allows compiling WebAssembly; inline scripts, `eval` and `new Function` stay
blocked. The WASM is an opaque blob inside `hash-wasm-argon2.min.js` (pinned by the
hash below, cross-checked against the JS implementation). Note that a page-level
(meta) CSP does not restrict a same-origin Worker script served without its own CSP
header (tested in Chromium; Safari and Firefox not tested), so do not rely on the
page CSP as a boundary for WASM in a Worker.

## Hashes

```
qrcode.min.js         sha256 c541ef06327885a8415bca8df6071e14189b4855336def4f36db54bde8484f36
                      sha512 CNgIRecGo7nphbeZ04Sc13ka07paqdeTu0WR1IM4kNcpmBAUSHSQX0FslNhTDadL4O5SAGapGt4FodqL8My0mA==  (base64)
html5-qrcode.min.js   sha256 660b12437b1d747e3e68b8be0685c08cb728140110ad213f167b14b66f8b1d8e
noble-ed25519.js      sha256 9a460a058fd595e7da3ad6f42038af27172c9fbf35b7d77e624e41a9a39b79ca
noble-mlkem.js        sha256 e97ae309b8882c1c3288cf69fb078a52505c4b746d5834f27796f4dce2f3f46a
noble-argon2.js       sha256 eaf25c37609fea59ea0286f0c503d3fd90762e9a97891461d439bfb6e827bd81
hash-wasm-argon2.min.js sha256 acfe11b015852f593aaddc51116f71dc7850e4551e6b34d42c1f88cf39635f03
```

npm tarball integrity of what the new files were built with:

```
@noble/post-quantum@0.7.1  sha512-+P9981IiAnVh+rmcubozzVwrEy3XsN/tMhTnvsjV9VDaYpOnNCqWqKo2FLWxbu92YHfjGIlE5XnW175UK+ln+Q==
@noble/hashes@2.4.0        sha512-X5XaVWZIBCT7HHZGm5I7ZQXDwLG+bGXuSrMQAW+7Zvl87h1kmc1ZB1VSRJcpUfoUrGQp4Fkoxm5kZ+Ms+aW+eA==
@noble/curves@2.4.0        sha512-P4/62zrgfH33CneE3Dn4WhJVA22YUU0eR51wKIan4NVRvwsA0YnPTwWGpNbpuacSujmSFLvyzpyuR30+fbq2Ew==
@noble/ciphers@2.4.0       sha512-AnjFn0Jv92laAkvMrghlFZq4qQCIN/4DxFV/eooqtC2YTjB7kBeLMS2T9KJX4Dn+ZVXLOwK0lSgqDtx9gvxtiw==
hash-wasm@4.13.0           sha512-GrWl7wsV46fKIXQZB5ebskLZLAmKL6d9RS0fspCxDeQyjoNu1AfTJTMLPOJyfzaQm0ldFiwFN21/w+sE/kgEFQ==
```

The three `noble-*` files are BUILDS, so their hashes depend on the esbuild
version (0.28.2 here); rebuilding with another esbuild gives different bytes but
the same code. The other files (`qrcode.min.js`, `html5-qrcode.min.js`,
`hash-wasm-argon2.min.js`) are unmodified upstream files.

hash-wasm-argon2.min.js: `npm install --save-exact hash-wasm@4.13.0`, then copy
`node_modules/hash-wasm/dist/argon2.umd.min.js` and compare the sha256.

## Rebuilding the noble-* bundles

noble-ed25519.js:

```
mkdir build && cd build && npm init -y
npm install --save-exact @noble/curves@1.4.0 esbuild
cp ../noble-entry.js entry.js
npx esbuild entry.js --bundle --minify --format=iife --target=es2020 \
    --legal-comments=none --outfile=noble-ed25519.js
```

noble-mlkem.js (entry file `noble-mlkem-entry.js`: `import { ml_kem768, ml_kem1024 }
from "@noble/post-quantum/ml-kem.js"; globalThis.mlkem = { ml_kem768, ml_kem1024 };`):

```
mkdir build-pq && cd build-pq && npm init -y
npm install --save-exact @noble/post-quantum@0.7.1 @noble/hashes@2.4.0 \
    @noble/curves@2.4.0 @noble/ciphers@2.4.0 esbuild
cp ../noble-mlkem-entry.js entry.js
npx esbuild entry.js --bundle --minify --format=iife --target=es2020 \
    --legal-comments=none --banner:js='<first line of noble-mlkem.js>' \
    --outfile=noble-mlkem.js
```

noble-argon2.js (entry file `noble-argon2-entry.js`: `import { argon2id, argon2idAsync }
from "@noble/hashes/argon2.js"; globalThis.nobleArgon2 = { argon2id, argon2idAsync };`):
same recipe with `npm install --save-exact @noble/hashes@2.4.0 esbuild`, the
entry copied to `entry.js`, and `--banner:js='<first line of noble-argon2.js>'`.

The post-quantum bundle carries its own copies of hashes, curves and ciphers 2.4.0;
it does not share code with noble-ed25519.js (curves 1.4.0), which stays as it is.

The old import was `https://esm.sh/@noble/curves@1.4.0/ed25519`; esm.sh resolved
the hashes dependency itself at request time, so the exact bytes could change
under a fixed URL. Here curves 1.4.0 pins hashes 1.4.0 exactly.

## Checked

- no `eval` / `new Function` reachable in any of them (html5-qrcode contains
  webpack's `new Function("return this")` globalThis fallback behind a
  `globalThis` check that is always true in a browser; it never runs) — so the
  CSP needs no `'unsafe-eval'`.
- no network access of their own (the URLs inside are SVG namespaces and
  comments).
- the two noble bundles contain no `eval` / `new Function` and no URLs beyond the
  author links in their license banners, and load and run under plain
  `script-src 'self'` (tested in Chromium 153 with that policy). hash-wasm contains
  no `eval` / `new Function` either; its WebAssembly module is embedded as data and
  needs `'wasm-unsafe-eval'` to compile.
- ML-KEM-768 and -1024 compared with an independent implementation (kyber-py 1.2.0,
  FIPS 203): keys derived from a 64-byte seed, ciphertexts for a fixed message,
  shared secrets and the implicit-rejection output of a tampered ciphertext are
  byte-identical, and decapsulation works in both directions.
- noble-argon2 output is identical to hash-wasm 4.13.0 (the reference used for the
  check) at 64, 256 and 512 MiB (t=3, p=2, 32 bytes). Timing on a slow 2-core test
  box at 512 MiB: 12 s blocking, 12.8 s with `asyncTick: 10`, longest event-loop
  stall about 14 ms. `argon2-bench.html` times it on a real device.

## Updating

Change the version, rebuild or re-download, update this table and the hashes,
and re-run the page once with the console open: a CSP violation shows up there.
Licenses for each package are in `LICENSE-*.txt` next to the files.
