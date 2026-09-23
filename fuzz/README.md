# Fuzz targets (cargo-fuzz, Linux CI)

Hostile-input boundaries only — parsers that consume bytes chosen by the
analyzed malware or the operator:

| target                       | boundary                                          |
|------------------------------|---------------------------------------------------|
| `parse_frame`                | IPC v1 frame header (agent ↔ user-actor pipe)     |
| `parse_config`               | strict TOML config (`C:\Agent.toml`)              |
| `decode_screenshot_payload`  | screenshot frame payload (`seq` + JPEG)           |

Run on a Linux host (libFuzzer needs `-fsanitize=fuzzer`; MSVC is not
supported):

```sh
cargo +nightly fuzz run parse_frame -- -max_total_time=300
cargo +nightly fuzz run parse_config -- -max_local_time=300
cargo +nightly fuzz run decode_screenshot_payload -- -max_total_time=300
```

The same call sites carry proptest coverage in the crates themselves
(`crates/protocol/tests/prop_wire.rs` and friends), so the invariants are
checked on every host on every commit; this crate adds long-running
coverage-guided search in CI. Corpora land in `artifacts/` (gitignored).
