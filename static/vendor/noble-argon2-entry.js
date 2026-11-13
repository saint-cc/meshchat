import { argon2id, argon2idAsync } from "@noble/hashes/argon2.js";
globalThis.nobleArgon2 = { argon2id, argon2idAsync };
