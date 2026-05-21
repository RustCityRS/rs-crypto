# rs-crypto — Cryptographic Primitives

Provides the two cryptographic systems used by the RuneScape protocol:

- **RSA** — Asymmetric encryption for login block protection (PKCS#8)
- **ISAAC** — Stream cipher for real-time packet opcode encryption/decryption

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [RSA](#rsa)
    - [Key Format (PKCS#8)](#key-format-pkcs8)
    - [RsaKey Struct](#rsakey-struct)
    - [Key Loading](#key-loading)
    - [Usage in Login Handshake](#usage-in-login-handshake)
- [ISAAC](#isaac)
    - [Algorithm Overview](#algorithm-overview)
    - [Rust API](#rust-api)
    - [Seed Derivation](#seed-derivation)
    - [C Implementation](#c-implementation)
    - [Usage in Packet Encryption](#usage-in-packet-encryption)
- [Build System](#build-system)
- [File Reference](#file-reference)

---

## Architecture Overview

```
                        ┌─────────────────────────────────┐
                        │         Game Client             │
                        └────────────┬────────────────────┘
                                     │
                          TCP/WebSocket Connection
                                     │
                    ┌────────────────┼────────────────────┐
                    │                │                    │
                    ▼                ▼                    ▼
            ┌──────────────┐ ┌──────────────┐  ┌──────────────────┐
            │  RSA Decrypt │ │ ISAAC Decode │  │  ISAAC Encode    │
            │  (login only)│ │ (all packets)│  │  (all packets)   │
            └──────┬───────┘ └──────┬───────┘  └────────┬─────────┘
                   │                │                   │
                   ▼                ▼                   ▼
            ┌──────────────────────────────────────────────────┐
            │                   rs-server                      │
            │                                                  │
            │  Login Phase:                                    │
            │    Client sends RSA-encrypted login block        │
            │    Server decrypts with private key              │
            │    Extracts ISAAC seeds from decrypted block     │
            │    Creates IsaacPair (encode + decode)           │
            │                                                  │
            │  Game Phase:                                     │
            │    Every packet opcode XOR'd with ISAAC output   │
            │    Encode cipher for server → client             │
            │    Decode cipher for client → server             │
            └──────────────────────────────────────────────────┘
```

### Login Handshake Flow

```
Client                                          Server
  │                                               │
  │◄──────────── 8-byte ISAAC seed ───────────────│
  │                                               │
  │  RSA-encrypt:                                 │
  │    magic byte (10)                            │
  │    4 x ISAAC seeds (i32)                      │
  │    UID                                        │
  │    username (base37)                          │
  │    password                                   │
  │                                               │
  │──────────── RSA-encrypted block ─────────────►│
  │                                               │
  │                              RSA decrypt with │
  │                              private key      │
  │                              Extract seeds    │
  │                              Create IsaacPair │
  │                                               │
  │◄──────────── Login response ──────────────────│
  │                                               │
  │  ═══════ All subsequent packets ═══════       │
  │  Opcodes XOR'd with ISAAC stream              │
  │◄─────────────────────────────────────────────►│
```

---

## RSA

### Key Format (PKCS#8)

The crate parses PKCS#8 DER-encoded private keys wrapped in PEM:

```
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASC...
-----END PRIVATE KEY-----
```

The ASN.1 structure:

```
SEQUENCE {                          // PKCS#8 outer wrapper
  INTEGER version                   // 0
  SEQUENCE { ... }                  // AlgorithmIdentifier (RSA)
  OCTET STRING {                    // Private key data
    SEQUENCE {                      // RSA private key
      INTEGER version               // 0
      INTEGER n                     // modulus
      INTEGER e                     // public exponent
      INTEGER d                     // private exponent
      INTEGER p                     // prime factor 1
      INTEGER q                     // prime factor 2
      INTEGER dp                    // d mod (p-1)
      INTEGER dq                    // d mod (q-1)
      INTEGER qinv                  // q^-1 mod p
    }
  }
}
```

### RsaKey Struct

```rust
pub struct RsaKey {
    pub n: BigInt,      // modulus
    pub e: BigInt,      // public exponent (typically 65537)
    pub d: BigInt,      // private exponent
    pub p: BigInt,      // first prime factor
    pub q: BigInt,      // second prime factor
    pub dp: BigInt,     // d mod (p-1), CRT optimization
    pub dq: BigInt,     // d mod (q-1), CRT optimization
    pub qinv: BigInt,   // q^-1 mod p, CRT optimization
}
```

All fields use `num_bigint::BigInt` for arbitrary-precision arithmetic.

### Key Loading

```rust
// Load from file
let key: RsaKey = load_rsa_key("keys/private.pem") ?;

// Or parse from string
let key: RsaKey = parse_rsa_key_from_pem( & pem_string) ?;
```

**Process:**

1. Strip PEM headers/footers and whitespace
2. Base64-decode to DER bytes
3. Parse outer PKCS#8 SEQUENCE
4. Extract inner OCTET STRING
5. Parse RSA private key SEQUENCE
6. Extract all 8 integer components as big-endian `BigInt`

### Usage in Login Handshake

The server loads the RSA key at startup and uses it to decrypt the client's login block. The login block contains ISAAC
seeds, username, and password. The `rs-io` crate's `Packet::rsadec()` method performs the actual modular exponentiation
using the key's `d` and `n` fields.

---

## ISAAC

### Algorithm Overview

ISAAC (Indirection, Shift, Accumulate, Add, and Count) is a cryptographically secure pseudorandom number generator
designed by Bob Jenkins. Properties:

| Property   | Value                                        |
|------------|----------------------------------------------|
| Output     | 32-bit integers                              |
| State size | 1 KB (256 x 32-bit words)                    |
| Batch size | 256 values per generation cycle              |
| Speed      | ~3 CPU cycles per output byte                |
| Seed size  | Up to 256 x 32-bit words (this crate uses 4) |

The algorithm maintains internal state (`randmem`) and produces output in batches of 256 values (`randrsl`). Each
generation cycle applies indirection, shifting, and accumulation across the full state, making the output stream
unpredictable without knowing the seed.

### Rust API

#### Isaac

```rust
// Create from 4 x u32 seed
let mut cipher = Isaac::new( & [seed0, seed1, seed2, seed3]);

// Get next random value
let value: u32 = cipher.next_int();

// Random in range [0, max)
let value: u32 = cipher.next_int_max(100);

// Random in range [min, max)
let value: i32 = cipher.next_int_range(10, 50);
```

#### IsaacPair

Paired encode/decode ciphers for bidirectional packet encryption:

```rust
// From client seeds (standard RuneScape protocol)
// Decode seed = [s0, s1, s2, s3]
// Encode seed = [s0+50, s1+50, s2+50, s3+50]
let pair = IsaacPair::from_client_seeds( & [s0, s1, s2, s3]);

// From session key (alternative derivation)
// Decode: [lo, hi, lo+1, hi+1]
// Encode: [lo^0xDEADBEEF, hi^0xCAFEBABE, lo-1, hi-1]
let (decode_seed, encode_seed) = IsaacPair::from_session_key(session_key);
let pair = IsaacPair::new( & decode_seed, & encode_seed);

// Use in packet processing
let opcode_mask = pair.decode.next_int();  // decrypt incoming
let opcode_mask = pair.encode.next_int();  // encrypt outgoing
```

### Seed Derivation

Two methods for creating encode/decode cipher pairs from shared secrets:

#### from_client_seeds (Standard Protocol)

```
Client seeds: [s0, s1, s2, s3]   (from RSA-encrypted login block)

Decode seed: [s0,    s1,    s2,    s3   ]   (exact client seeds)
Encode seed: [s0+50, s1+50, s2+50, s3+50]   (offset by 50)
```

The `+50` offset ensures encode and decode streams never produce identical sequences.

#### from_session_key (Alternative)

```
Session key: u64

key_low  = session_key & 0xFFFFFFFF
key_high = session_key >> 32

Decode seed: [key_low,              key_high,
              key_low + 1,          key_high + 1          ]

Encode seed: [key_low ^ 0xDEADBEEF, key_high ^ 0xCAFEBABE,
              key_low - 1,           key_high - 1          ]
```

### C Implementation

The core ISAAC algorithm is implemented in C (`csrc/rand.c`) for performance, compiled at optimization level 3, and
linked via FFI.

#### Core Generation (`isaac()`)

```
For each generation cycle (produces 256 values):

  b += ++c                           // increment counter, feed into b

  For each of 256 state positions:
    x = mem[i]                       // load state
    a = f(a, i) + mem[i+128 mod 256] // mix accumulator
    mem[i] = y = ind(mem, x) + a + b // update state via indirection
    rsl[i] = b = ind(mem, y>>8) + x  // produce output via indirection
```

The mixing function `f(a, i)` cycles through four operations:

| i mod 4 | Operation        |
|---------|------------------|
| 0       | `a ^= (a << 13)` |
| 1       | `a ^= (a >> 6)`  |
| 2       | `a ^= (a << 2)`  |
| 3       | `a ^= (a >> 16)` |

#### Initialization (`randinit()`)

```
1. Set a,b,c,d,e,f,g,h = 0x9E3779B9 (golden ratio)
2. Scramble: 4 iterations of mix(a,b,c,d,e,f,g,h)
3. First pass: mix seed values into state memory
4. Second pass: mix state memory into itself
5. Generate first batch of 256 output values
```

The golden ratio constant `0x9E3779B9` provides initial entropy dispersion.

### Usage in Packet Encryption

```
Packet Structure (on wire):
┌──────────────────┬─────────────┐
│ opcode (1 byte)  │ payload     │
│ XOR'd with ISAAC │ (plaintext) │
└──────────────────┴─────────────┘

Encoding (server → client):
  wire_opcode = real_opcode ^ (isaac_encode.next_int() & 0xFF)

Decoding (client → server):
  real_opcode = wire_opcode ^ (isaac_decode.next_int() & 0xFF)
```

Both sides maintain synchronized ISAAC streams. Since ISAAC is deterministic with the same seed, and both sides derive
seeds from the same handshake data, the streams stay in lockstep as long as both sides consume one value per packet.

---

## Build System

```rust
// build.rs
fn main() {
    cc::Build::new()
        .file("csrc/rand.c")
        .include("csrc")
        .opt_level(3)        // maximum optimization
        .warnings(false)
        .compile("isaac");   // produces libisaac.a
}
```

The C code is compiled once at build time into a static library. The Rust FFI layer then calls into `randinit()` and
`isaac()` with zero runtime overhead beyond the function call.

---

## File Reference

```
rs-crypto/
  Cargo.toml           # deps: thiserror, simple_asn1, base64, num-bigint
  build.rs             # compiles csrc/rand.c via cc crate
  src/
    lib.rs             # pub mod isaac; pub mod rsa;
    rsa.rs             # RsaKey, PEM/PKCS#8 parsing, key loading
    isaac.rs           # Isaac, IsaacPair, FFI bindings, seed derivation
  csrc/
    rand.c             # ISAAC algorithm (Bob Jenkins, public domain)
    rand.h             # RandCtx struct, RANDSIZ constant
    standard.h         # ub4/ub1/word type definitions
```

### Dependencies

| Crate         | Version | Purpose                             |
|---------------|---------|-------------------------------------|
| `simple_asn1` | 0.6     | ASN.1/DER parsing for PKCS#8        |
| `base64`      | 0.22    | PEM Base64 decoding                 |
| `num-bigint`  | 0.4     | Big integer arithmetic for RSA      |
| `cc`          | 1.2     | C compiler integration (build-time) |
