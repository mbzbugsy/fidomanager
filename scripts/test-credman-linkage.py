#!/usr/bin/env python3
"""Deterministic negative controls for credential/PIN symbol attribution; no hardware."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("verifier", Path(__file__).with_name("verify-libfido2-linkage.py"))
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)
names = ["fido_credman_" + suffix for suffix in verifier.CREDMAN_SYMBOLS]
symbols = "\n".join("000 T _" + name for name in names)
link_map = "\n".join("000 0 [ 9] _" + name for name in names)
verifier.verify_credman_symbols(symbols, link_map, "9")
for bad_symbols, bad_map in (
    (symbols.replace("T _" + names[0], "U _" + names[0]), link_map),
    (symbols, link_map.replace("[ 9] _" + names[-1], "[ 8] _" + names[-1])),
    (symbols, "# Dead Stripped Symbols:\n" + link_map),
    (symbols, link_map.replace(names[0], "unrelated")),
):
    try:
        verifier.verify_credman_symbols(bad_symbols, bad_map, "9")
    except RuntimeError:
        pass
    else:
        raise AssertionError("invalid M3 attribution passed")
print("PASS: all M3 symbols; missing, unresolved, other-object and dead-stripped controls rejected")

pin_archive = "/cargo/private-libfido2/libfidomanager_fido2_bounded.a"
pin_symbols = "000 T _fido_dev_set_pin"
pin_map = "[ 12] " + pin_archive + "(pin.c.o)\n000 0 [ 12] _fido_dev_set_pin"
verifier.verify_pin_symbol(pin_symbols, pin_map, pin_archive)
for bad_symbols, bad_map in (
    (pin_symbols.replace("T _", "U _"), pin_map),
    (pin_symbols, pin_map.replace("[ 12] _", "[ 13] _")),
    (pin_symbols, pin_map.replace(pin_archive, "/opt/homebrew/lib/libfido2.a")),
    (pin_symbols, "[ 12] " + pin_archive + "(pin.c.o)\n# Dead Stripped Symbols:\n000 0 [ 12] _fido_dev_set_pin"),
    (pin_symbols, pin_map.replace("pin.c.o", "unrelated.c.o")),
):
    try:
        verifier.verify_pin_symbol(bad_symbols, bad_map, pin_archive)
    except RuntimeError:
        pass
    else:
        raise AssertionError("invalid PIN attribution passed")
print("PASS: PIN symbol unresolved, wrong object/archive and dead-stripped controls rejected")
