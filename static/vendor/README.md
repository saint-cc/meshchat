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

## Hashes

```
qrcode.min.js         sha256 c541ef06327885a8415bca8df6071e14189b4855336def4f36db54bde8484f36
                      sha512 CNgIRecGo7nphbeZ04Sc13ka07paqdeTu0WR1IM4kNcpmBAUSHSQX0FslNhTDadL4O5SAGapGt4FodqL8My0mA==  (base64)
html5-qrcode.min.js   sha256 660b12437b1d747e3e68b8be0685c08cb728140110ad213f167b14b66f8b1d8e
noble-ed25519.js      sha256 9a460a058fd595e7da3ad6f42038af27172c9fbf35b7d77e624e41a9a39b79ca
```

`noble-ed25519.js` is a BUILD, so its hash depends on the esbuild version
(0.28.2 here); rebuilding with another esbuild gives different bytes but the
same code. The two other files are unmodified upstream files.

## Rebuilding noble-ed25519.js

```
mkdir build && cd build && npm init -y
npm install --save-exact @noble/curves@1.4.0 esbuild
cp ../noble-entry.js entry.js
npx esbuild entry.js --bundle --minify --format=iife --target=es2020 \
    --legal-comments=none --outfile=noble-ed25519.js
```

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

## Updating

Change the version, rebuild or re-download, update this table and the hashes,
and re-run the page once with the console open: a CSP violation shows up there.
Licenses for each package are in `LICENSE-*.txt` next to the files.
