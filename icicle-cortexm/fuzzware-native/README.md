# fuzzware-native

Cortex-M NVIC emulation based based on the Fuzzware native library: [fuzzware-emulator/harness/fuzzware_harness/native](
https://github.com/fuzzware-fuzzer/fuzzware-emulator/tree/075dbb52f3ba4c20549e81fbee27e8e21086ae56/harness/fuzzware_harness/native). With the following modifications.

- Non-NVIC MMIO handling has been removed.
- Emulator integration is done via function calls to allow binding with Icicle.
- All global variables have been replaced with thread-safe context structs.
- Snapshotting must now be done by directly calling the snapshotting functions.
- Several compile time configuration options have been moved to runtime checks.

All modifications are made available under the existing Apache 2.0 licence (see [LICENCE](./LICENCE)).