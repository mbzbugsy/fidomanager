# H0 Option A timing report

- OS: macos 26.5.2 (25F84), Mac16,1 aarch64
- Scratch filesystem: apfs
- libfido2: `b974e7cf2ee7392134cc12c08b76a068cf250dd8`
- Tool: 0.1.0 `fidomanager-h0-timing-v1`

All values in milliseconds. Nearest-rank percentiles; every value is an observed sample.

## Durability only (production replace, no device)

| component | n | min | median | p95 | max |
|---|---|---|---|---|---|
| t5_durable_replace | 200 | 5.807 | 7.751 | 8.746 | 14.872 |

## Yubico YubiKey FIDO+CCID (VID 1050 PID 0406, AAGUID d7781e5de35346aaafe23ca49f13332a, firmware 329476)

Model label groups samples only; it is not identity or authority.

Measured: 20. Aborted: none.

| component | n | min | median | p95 | max |
|---|---|---|---|---|---|
| t1_insertion_to_manifest | 20 | 0.572 | 1.501 | 6.460 | 8.324 |
| t2_manifest_to_open | 20 | 223.564 | 225.080 | 226.146 | 227.805 |
| t3_open_to_get_info | 20 | 15.819 | 15.994 | 16.046 | 16.052 |
| t4_validation | 20 | 0.007 | 0.015 | 0.020 | 0.032 |
| t5_durable_replace | 20 | 8.688 | 11.662 | 13.885 | 14.530 |
| t6_sync_to_would_dispatch | 20 | 0.032 | 0.050 | 0.078 | 0.078 |
| **total T1–T6** | 20 | 249.751 | 254.129 | 258.234 | 261.507 |
| (manifest call) | 20 | 1.201 | 10.935 | 16.814 | 16.844 |

Verdict: **OptionAViable**. Window 5000 ms; acceptable host path ≤ 1325.0 ms; runtime budget 2650.0 ms; required 2873.7 ms.
