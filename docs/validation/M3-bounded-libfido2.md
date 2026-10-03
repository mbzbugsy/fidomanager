# M3 prerequisite: bounded native credential-management allocation

Issue #22. macOS-only production scope. Starting main:
`effd16ff1673f9c3b085dafa5991fe39114d0232`.
Branch: `feature/m3-bounded-libfido2`. Validation date: 2026-10-04
(Europe/Stockholm). #14 remains blocked until this prerequisite is reviewed and
merged; #11 remains open. This is not M3 credential inspection or UI.

## Source and patch

The source baseline is libfido2 **1.17.0**, exact upstream commit
`b974e7cf2ee7392134cc12c08b76a068cf250dd8`.
`native/libfido2/source.lock.json` pins the commit archive URL, SHA-256 of the
archive, patch and upstream/patched `src/credman.c`, and the production ceiling.
The downloaded archive SHA-256 is
`a7c340900cb58b6905e12855944069024f39707f9573d52d4830a4561a50819a`.

The entire source delta is
[`credman-allocation-bound.patch`](../../native/libfido2/credman-allocation-bound.patch):

- One constant, `FIDOMANAGER_CREDMAN_MAX_ENTRIES = 256`.
- At the start of `credman_grow_array`, reject `n > 256` before
  `recallocarray` and before the existing early no-growth return.
- A private scalar identity probe in that same translation unit returns that
  constant. Its name also identifies the 1.17.0 baseline; it is not an upstream
  public API and carries no runtime paths, counts from a device, or secrets.

Both `credman_parse_rp_count` and `credman_parse_rk_count` use this shared helper.
No existing state, decoding, size/overflow or fuzz sanity checks are removed.
`FUZZ=OFF` is explicit in the production build; the production guard is
unconditional. The existing fuzz-only ceiling remains unchanged. The new failure
returns through the existing native error path without logging the supplied count.
No mutation command semantics, worker wire contract, renderer command/DTO,
PIN handling or authentication acquisition semantics change.

256 is an explicit application compatibility/resource choice, not a CTAP maximum.
It permits a substantial inventory while placing a small fixed upper bound on each
native RP or per-RP resident-key array. It deliberately rejects devices that report
larger arrays. Raising it requires review of the patch, resource budget and tests.
M3 must still independently bound total credentials across RPs, string/ID copies,
and protocol payloads. This prerequisite does not claim that every native
allocation, transitive decoder or aggregate future inventory is now bounded by 256.

Worker isolation alone was insufficient: a tiny native reply can supply a large
integer count and force an allocation attempt before Rust regains control. A native
deadline, post-return accessor checks, JSON frame size or eventual worker kill
cannot reject that allocation in advance. A metadata preflight cannot constrain a
contradictory subsequent count from an untrusted device. The patch places rejection
at the allocation boundary itself.

## Build and linkage

`python3 scripts/build-libfido2.py fetch` downloads the exact commit archive into
ignored `target/native-sources/`. It checks the digest before publishing the cache;
a missing/corrupt cache fails Cargo builds instead of triggering network access or
falling back to the system library. Archive extraction rejects traversal, links and
special files and bounds the downloaded/unpacked data. Patch application uses
`git apply --check`, then `git apply`, followed by the expected patched-file digest;
a changed source/context or patch cannot be silently accepted.

On macOS, `crates/fido-libfido2/build.rs` automatically builds freshly verified source
under its Cargo `OUT_DIR`. CMake uses a fixed Release/static-only configuration,
native IOKit HID, no PCSC/HIDAPI/NFC, no tools/examples/tests/manpages, no fuzzing,
an explicit Xcode clang, target architecture and macOS deployment target 11.0.
Caller compiler/link flags and CMake toolchain/generator overrides are removed.
Source/build prefix maps and deterministic archive timestamps remove temporary-path
and time dependence. `build-identity.json` records source/patch/archive digests,
baseline, bound, architecture, compiler and dependency versions **without local
absolute paths**. Nothing from this metadata is exposed by the application.

The worker links the uniquely named `libfidomanager_fido2_bounded.a` with Cargo
`static:-bundle`; the archive remains separately attributable in the final link map.
macOS FFI declarations do not request `-lfido2`. `LIBFIDO2_LIB_DIR` is rejected.
Only transitive **libcrypto/libcbor** dependency discovery uses pkg-config; neither
Homebrew nor any system **libfido2** supplies production worker symbols. The adapter
references the private probe and checks 256 before initializing libfido2. An
unpatched compatible ABI cannot resolve that symbol. The link map connects the
retained probe to the actual private archive's `credman.c.o`, whose archive digest
must match the path-free build identity. `otool` must show no libfido2 dylib, and
`nm` must show the probe, `fido_init` and `fido_dev_get_puat` defined in the worker
with no unresolved FIDO symbols.

Reproducibility here means verified identical source/patch/configuration and
byte-identical archives on repeated builds with the **same** compiler, SDK and
transitive dependency environment. It is not a claim of hermetic or cross-toolchain
binary identity. Dependency versions are recorded; macOS SDK, CMake, compiler,
OpenSSL and libcbor remain build prerequisites. Two separate build paths are tested
for byte identity in macOS CI.

The source-fetch/patch/test mechanism is portable. Linux production deliberately
retains its existing discovery-only system-library policy; enabling this private
build on Linux is later work. Linux CI tests the exact patched count functions but
does not claim Linux M2/M3 support. Windows is not enabled.

## Development and CI

On macOS, prerequisites: Python 3.9+, Xcode Command Line Tools, CMake, pkg-config,
OpenSSL and libcbor. No installation of libfido2 is required for the production
build. The archive-link negative test additionally uses an installed unpatched
libfido2 as a control; macOS CI installs it for that purpose only.

```sh
brew install cmake pkg-config openssl@3 libcbor
python3 scripts/build-libfido2.py fetch
cargo build -p fido-worker --locked
python3 scripts/test-libfido2.py --rebuild
python3 scripts/verify-libfido2-linkage.py target/debug/fido-worker
```

The source cache lives at the workspace's `target/native-sources` even when
`CARGO_TARGET_DIR` relocates Cargo outputs. After fetching, native builds and source
tests require no source network access. CI fetches the small checksum-pinned archive
rather than committing a generated source tree or tarball. A network outage on a
fresh runner fails preparation explicitly; an already verified cache can be retained
for offline builds. An archive regenerated differently upstream fails its pinned
checksum and needs an intentional source review/update.

## Deterministic evidence

`native/libfido2/tests/credman_bounds.c` compiles the exact patched growth/count
function bodies and exact upstream unsigned-count decoder extracted from verified
source. It uses actual upstream RP/credential structs and libcbor values; parser
logic is not modeled. A substituted allocator records calls and refuses all
oversized requests without attempting a large allocation. This is a function-level
native test, not a full HID/CTAP exchange.

Both RP and resident-key paths cover **0, 1, 255, 256, 257, 1,000,000,000,
UINT32_MAX and UINT64_MAX**. Counts at/below 256 succeed; over-limit counts fail
with **zero allocator calls** and unchanged empty array state. Existing populated-
array growth rejection, no-growth behavior, and non-unsigned count rejection are
also tested. The unpatched source negative control reaches the refusing allocator
for the oversized values, demonstrating the instrumentation distinguishes the
original vulnerability. Corrupt/missing archives, a corrupt patch and changed
patch context fail closed. Private-archive linkage succeeds and the unpatched
system-library linkage fails on the required probe symbol.

Local macOS validation passed:

| Check | Result |
| --- | --- |
| `cargo fmt --all --check` | Passed |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Passed |
| `cargo test --workspace --all-targets --locked` | Passed, 239 tests |
| `node scripts/check-renderer-boundary.mjs` | Passed |
| `node scripts/test-renderer-boundary.mjs` | Passed |
| `pnpm check` | Passed, zero errors/warnings |
| `pnpm test` | Passed with intentional no-test-files behavior; no frontend coverage claimed |
| `pnpm build` | Passed |
| `pnpm exec prettier --check .` | Passed |
| `git diff --check` | Passed |
| `python3 scripts/test-libfido2.py --rebuild` | Passed, both parser paths and byte-identical separate-path archives |
| `python3 scripts/test-libfido2.py --build-dir target/native-libfido2-check` | Passed, source/patch negatives, real Cargo override rejection and archive/system link controls |
| `cargo build -p fido-worker --locked` | Passed |
| `python3 scripts/verify-libfido2-linkage.py target/debug/fido-worker` | Passed, private archive/object attribution and no libfido2 dylib |

Repeated native archives on this arm64 workstation had SHA-256
`9ceb6c59a9679806e899d1714ef46f9806d0491fc1c6bc5f7ad9030ae71b75ed`.
Build identity: Apple clang 21.0.0 (`clang-2100.1.1.101`), CMake 4.4.4,
libcrypto 3.6.5, libcbor 0.14.0, zlib 1.2.12. This digest is local reproducibility
evidence, not a universal artifact pin across SDK/compiler versions.

The initial sandboxed Rust test attempt failed the existing process-counter
positive control because `ps` was denied. The complete suite passed when rerun
with process visibility enabled; no test assertion was weakened. Linux/macOS CI
jobs were updated but remote CI results are not claimed by this local report.
No real hardware/PIN/mutation test is needed or performed for this prerequisite.

## RP text API note for #14

Confirmed in the pinned public header: `fido_credman_rp_id(...)` returns
`const char *`; there is **no RP-text length accessor**. Hash access has a separate
pointer/length pair. The pinned `cbor_string_copy` allocates `len + 1`, copies the
CBOR string bytes and writes a terminating NUL. Future M3 must use a narrow bounded
NUL-string wrapper relying on this invariant, reject a missing terminator within
its application limit, validate UTF-8/control characters, preserve missing versus
malformed states, verify exact text against the authoritative 32-byte hash, and
copy before `fido_credman_rp_free`. This PR implements no string extraction.

Pinned upstream sources:

- [credman.c](https://github.com/Yubico/libfido2/blob/b974e7cf2ee7392134cc12c08b76a068cf250dd8/src/credman.c)
- [Public credential-management header](https://github.com/Yubico/libfido2/blob/b974e7cf2ee7392134cc12c08b76a068cf250dd8/src/fido/credman.h)
- [cbor.c](https://github.com/Yubico/libfido2/blob/b974e7cf2ee7392134cc12c08b76a068cf250dd8/src/cbor.c)

## Packaging implications and review gate

Static libfido2 requires no dylib installation/relocation or libfido2 load path in
the final worker. libcrypto and libcbor remain dynamic dependencies in development;
the existing unsigned/unbundled app configuration is unchanged. Release packaging
must bundle/relocate/sign those dependencies, preserve the pinned source/patch
identity, retain native license notices, verify linkage before stripping/signing,
and re-sign the worker when updating the statically embedded libfido2. The retained
upstream BSD notice is `native/libfido2/LICENSE.upstream`; release materials must also
retain all applicable notices from the fetched source and transitive dependencies.
Signing/notarization and complete distribution packaging are separate work.

Independent patch/linkage security review is required before merge, per #22.
The PR remains Draft; no merge or issue closure is performed here.

## Exact changed files

- `.gitattributes` (whitespace handling scoped to unified-diff patch context).
- `.github/workflows/ci.yml`.
- `README.md`.
- `crates/fido-libfido2/build.rs`.
- `crates/fido-libfido2/src/lib.rs`.
- `crates/fido-libfido2/src/native/authentication.rs`.
- `crates/fido-worker/Cargo.toml`.
- `crates/fido-worker/build.rs`.
- `native/libfido2/LICENSE.upstream`.
- `native/libfido2/credman-allocation-bound.patch`.
- `native/libfido2/source.lock.json`.
- `native/libfido2/tests/credman_bounds.c`.
- `scripts/build-libfido2.py`.
- `scripts/test-libfido2.py`.
- `scripts/verify-libfido2-linkage.py`.
- `docs/validation/M3-bounded-libfido2.md`.
