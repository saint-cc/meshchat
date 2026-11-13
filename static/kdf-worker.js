/* ═════════════════════════════════════════════════════════════
   MESHCHAT — kdf-worker.js
   Runs the identity KDF (Argon2id, see ARGON2_PARAMS in meshchat-lib.js) off
   the main thread. 512 MiB / t=3 / p=2 takes seconds even in WASM and tens of
   seconds in the pure-JS fallback — on the page thread that would freeze the
   login screen, and the browser would offer to kill the tab.

   One worker per derivation: meshchat-lib.js (runKdfWorker) starts it, sends
   ONE message and terminates the worker as soon as it answers, so the 512 MiB
   goes back to the OS at once instead of sitting in an idle worker.

   PROTOCOL
     page -> worker   { type: "derive", password: Uint8Array, salt: Uint8Array,
                        params: { memoryKiB, iterations, parallelism, hashLength } }
                      (both buffers are TRANSFERRED: the page keeps no copy)
     worker -> page   { type: "backend",  backend: "wasm" | "js" }       once, before the work
                      { type: "progress", pct: 0..100 }                  JS backend only
                      { type: "done",     key: Uint8Array, backend }
                      { type: "error",    kind: "oom" | "selftest" | "other", message }

   BACKENDS. hash-wasm (WASM) first, pure-JS noble as the fallback, both
   vendored (./vendor/, see vendor/README). They are bit-for-bit the same
   function — checked against the reference C implementation (argon2-cffi) at
   the real parameters — so which one ran never changes the identity.
   A backend is only trusted after it reproduces a known-answer vector at tiny
   parameters (ARGON2_KAT). That is what turns "WASM blocked by a CSP header /
   unsupported / broken build" into a quiet fall-back to JS, and a JS build
   that computes the wrong thing into a hard stop: a silently wrong KDF would
   not be an error, it would be a login to a different, empty identity.

   OUT OF MEMORY is NOT a reason to fall back: the JS backend needs the same
   512 MiB the WASM one just failed to get. It is reported as kind "oom" and
   the page shows a "not enough memory" message.
═════════════════════════════════════════════════════════════ */
"use strict";

const WASM_SCRIPT = "./vendor/hash-wasm-argon2.min.js";   // sets globalThis.hashwasm
const JS_SCRIPT   = "./vendor/noble-argon2.js";           // sets globalThis.nobleArgon2 = { argon2id, argon2idAsync }

// Known-answer test. Inputs and the expected output were computed with
// argon2-cffi (the reference C code), @noble/hashes 2.4.0 and hash-wasm — all
// three agree. Tiny memory so the self-test costs a few ms, but p=2 and t=2
// so it still exercises multiple lanes and passes.
const ARGON2_KAT = {
  password: new TextEncoder().encode("meshchat kat passphrase"),
  salt:     Uint8Array.from({ length: 32 }, (_, i) => i),
  params:   { memoryKiB: 64, iterations: 2, parallelism: 2, hashLength: 32 },
  expected: "f9dc5029b9b47284722fdd47694527e436bb9b408518107fe72c55e151dbc034",
};

const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");

// Out-of-memory looks like a RangeError ("Array buffer allocation failed",
// "WebAssembly.Memory.grow(): Maximum memory size exceeded") in every engine
// we know of, with the wording varying — hence the message test as well.
const isOom = (e) => e instanceof RangeError || /memory|alloc/i.test(String(e && e.message));

const backends = {
  wasm: {
    load() {
      if (typeof WebAssembly !== "object") throw new Error("WebAssembly unavailable");
      importScripts(WASM_SCRIPT);
      if (typeof self.hashwasm?.argon2id !== "function") throw new Error("hash-wasm did not define hashwasm.argon2id");
    },
    async run(password, salt, p) {
      return new Uint8Array(await self.hashwasm.argon2id({
        password, salt,
        parallelism: p.parallelism, iterations: p.iterations,
        memorySize: p.memoryKiB,           // hash-wasm counts KiB, like the RFC's m
        hashLength: p.hashLength, outputType: "binary",
      }));
    },
  },
  js: {
    load() {
      importScripts(JS_SCRIPT);
      if (typeof self.nobleArgon2?.argon2idAsync !== "function") throw new Error("noble did not define nobleArgon2.argon2idAsync");
    },
    // argon2idAsync yields to the event loop now and then, which is what lets
    // the progress messages below actually leave the worker while it runs.
    async run(password, salt, p, onPct) {
      let last = -1;
      return Uint8Array.from(await self.nobleArgon2.argon2idAsync(password, salt, {
        t: p.iterations, m: p.memoryKiB, p: p.parallelism, dkLen: p.hashLength,
        onProgress: onPct && ((frac) => { const pct = Math.min(100, Math.floor(frac * 100)); if (pct !== last) { last = pct; onPct(pct); } }),
      }));
    },
  },
};

async function selfTest(b) {
  // copies: a backend must not be able to scribble on the shared KAT inputs
  const out = await b.run(ARGON2_KAT.password.slice(), ARGON2_KAT.salt.slice(), ARGON2_KAT.params);
  return hex(out) === ARGON2_KAT.expected;
}

// -> "wasm" | "js". Throws { kind: "selftest" } only when the JS backend is
// present but wrong; a WASM that is missing, blocked or wrong just means "use JS".
async function pickBackend() {
  try {
    backends.wasm.load();
    if (await selfTest(backends.wasm)) return "wasm";
  } catch (e) { /* WASM not usable here — fall through to JS */ }
  backends.js.load();   // a missing/broken JS build throws -> reported as "other"
  if (!(await selfTest(backends.js))) {
    const err = new Error("Argon2id self-test failed — refusing to derive keys with a KDF that computes the wrong answer");
    err.kind = "selftest";
    throw err;
  }
  return "js";
}

const validParams = (p) => p && ["memoryKiB", "iterations", "parallelism", "hashLength"].every((k) => Number.isInteger(p[k]) && p[k] > 0);

self.onmessage = async (ev) => {
  const m = ev.data;
  if (!m || m.type !== "derive") return;
  const { password, salt, params } = m;
  try {
    if (!(password instanceof Uint8Array) || !password.length || !(salt instanceof Uint8Array) || salt.length < 8 || !validParams(params)) {
      throw new Error("bad derive request");
    }
    const name = await pickBackend();
    self.postMessage({ type: "backend", backend: name });
    const onPct = name === "js" ? (pct) => self.postMessage({ type: "progress", pct }) : null;
    let key, used = name;
    try {
      key = await backends[name].run(password, salt, params, onPct);
    } catch (e) {
      // A WASM failure that is NOT memory (unexpected, since its self-test
      // passed) gets one retry on the JS backend — same function, same
      // output. Memory failures are final: JS needs the same 512 MiB.
      if (name !== "wasm" || isOom(e)) throw e;
      backends.js.load();
      if (!(await selfTest(backends.js))) throw e;
      used = "js";
      self.postMessage({ type: "backend", backend: used });
      key = await backends.js.run(password, salt, params, (pct) => self.postMessage({ type: "progress", pct }));
    }
    self.postMessage({ type: "done", key, backend: used }, [key.buffer]);
  } catch (e) {
    self.postMessage({ type: "error", kind: e && e.kind ? e.kind : isOom(e) ? "oom" : "other", message: String((e && e.message) || e) });
  } finally {
    // Best effort: the page's copy was transferred away, this is the worker's.
    try { if (m.password instanceof Uint8Array) m.password.fill(0); } catch (_) {}
  }
};