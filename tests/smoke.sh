#!/bin/sh
set -eu

ROOT=tests/tmp
rm -rf "$ROOT"
mkdir -p "$ROOT"

printf 'DEFCON demo payload\nline two\n' > "$ROOT/plain.txt"
./build/eyas-crypt seal "$ROOT/plain.txt" "$ROOT/plain.eyas" --pass 'correct horse battery staple'
./build/eyas-crypt info "$ROOT/plain.eyas" | grep -q 'cipher=chacha20'
if ./build/eyas-crypt open "$ROOT/plain.eyas" "$ROOT/bad.txt" --pass wrong 2>/dev/null; then
    echo "wrong passphrase opened vault" >&2
    exit 1
fi
./build/eyas-crypt open "$ROOT/plain.eyas" "$ROOT/out.txt" --pass 'correct horse battery staple'
cmp "$ROOT/plain.txt" "$ROOT/out.txt"

./build/eyas-crypt enroll-device "$ROOT/device.key" >/dev/null
./build/eyas-crypt enroll-device "$ROOT/other.key" >/dev/null
./build/eyas-crypt seal "$ROOT/plain.txt" "$ROOT/device-bound.eyas" --pass 'device pass' --device "$ROOT/device.key"
./build/eyas-crypt info "$ROOT/device-bound.eyas" | grep -q 'policy=passphrase+device-key'
if ./build/eyas-crypt open "$ROOT/device-bound.eyas" "$ROOT/no-device.txt" --pass 'device pass' 2>/dev/null; then
    echo "device-bound vault opened without device key" >&2
    exit 1
fi
if ./build/eyas-crypt open "$ROOT/device-bound.eyas" "$ROOT/wrong-device.txt" --pass 'device pass' --device "$ROOT/other.key" 2>/dev/null; then
    echo "device-bound vault opened with wrong device key" >&2
    exit 1
fi
./build/eyas-crypt open "$ROOT/device-bound.eyas" "$ROOT/device-out.txt" --pass 'device pass' --device "$ROOT/device.key"
cmp "$ROOT/plain.txt" "$ROOT/device-out.txt"

# - threshold split-key vaults (Shamir 2-of-3) -
./build/eyas-crypt seal "$ROOT/plain.txt" "$ROOT/split.eyas" --pass 'team pass' --threshold 2 --shares 3 >/dev/null
./build/eyas-crypt info "$ROOT/split.eyas" | grep -q 'policy=passphrase+threshold'
./build/eyas-crypt info "$ROOT/split.eyas" | grep -q 'threshold=2'
# any 2 of 3 shares + passphrase reconstruct
./build/eyas-crypt open "$ROOT/split.eyas" "$ROOT/split-out.txt" --pass 'team pass' --share "$ROOT/split.eyas.share1" --share "$ROOT/split.eyas.share3"
cmp "$ROOT/plain.txt" "$ROOT/split-out.txt"
# a single share is below threshold and must fail
if ./build/eyas-crypt open "$ROOT/split.eyas" "$ROOT/split-bad.txt" --pass 'team pass' --share "$ROOT/split.eyas.share1" 2>/dev/null; then
    echo "single share opened threshold vault" >&2
    exit 1
fi
# correct shares but wrong passphrase must fail
if ./build/eyas-crypt open "$ROOT/split.eyas" "$ROOT/split-bad.txt" --pass 'wrong' --share "$ROOT/split.eyas.share1" --share "$ROOT/split.eyas.share2" 2>/dev/null; then
    echo "wrong passphrase opened threshold vault" >&2
    exit 1
fi
# shares from a different vault must fail (group mismatch)
./build/eyas-crypt seal "$ROOT/plain.txt" "$ROOT/split2.eyas" --pass 'team pass' --threshold 2 --shares 3 >/dev/null
if ./build/eyas-crypt open "$ROOT/split.eyas" "$ROOT/split-bad.txt" --pass 'team pass' --share "$ROOT/split.eyas.share1" --share "$ROOT/split2.eyas.share2" 2>/dev/null; then
    echo "mismatched shares opened threshold vault" >&2
    exit 1
fi

# - Argon2id KDF matches the RFC 9106 test vector -
./build/eyas-crypt selftest >/dev/null

# - time-lock vault (short delay) -
./build/eyas-crypt seal "$ROOT/plain.txt" "$ROOT/tl.eyas" --pass 'tl pass' --timelock 0.3 >/dev/null
./build/eyas-crypt info "$ROOT/tl.eyas" | grep -q 'policy=passphrase+timelock'
./build/eyas-crypt open "$ROOT/tl.eyas" "$ROOT/tl-out.txt" --pass 'tl pass'
cmp "$ROOT/plain.txt" "$ROOT/tl-out.txt"
if ./build/eyas-crypt open "$ROOT/tl.eyas" "$ROOT/tl-bad.txt" --pass 'wrong' 2>/dev/null; then
    echo "wrong passphrase opened time-lock vault" >&2
    exit 1
fi

# - multi-recipient vault: any of N passphrases opens it -
./build/eyas-crypt seal "$ROOT/plain.txt" "$ROOT/mr.eyas" --recipient alice --recipient bob --recipient carol >/dev/null
./build/eyas-crypt info "$ROOT/mr.eyas" | grep -q 'policy=multi-recipient'
./build/eyas-crypt open "$ROOT/mr.eyas" "$ROOT/mr-a.txt" --pass alice && cmp "$ROOT/plain.txt" "$ROOT/mr-a.txt"
./build/eyas-crypt open "$ROOT/mr.eyas" "$ROOT/mr-c.txt" --pass carol && cmp "$ROOT/plain.txt" "$ROOT/mr-c.txt"
if ./build/eyas-crypt open "$ROOT/mr.eyas" "$ROOT/mr-bad.txt" --pass mallory 2>/dev/null; then
    echo "non-recipient opened multi-recipient vault" >&2
    exit 1
fi

# - Argon2id vault roundtrip -
./build/eyas-crypt seal "$ROOT/plain.txt" "$ROOT/a2.eyas" --pass 'a2 pass' --kdf argon2id --argon-m 8192 >/dev/null
./build/eyas-crypt info "$ROOT/a2.eyas" | grep -q 'kdf=argon2id'
./build/eyas-crypt open "$ROOT/a2.eyas" "$ROOT/a2-out.txt" --pass 'a2 pass'
cmp "$ROOT/plain.txt" "$ROOT/a2-out.txt"
if ./build/eyas-crypt open "$ROOT/a2.eyas" "$ROOT/a2-bad.txt" --pass 'wrong' 2>/dev/null; then
    echo "wrong passphrase opened argon2id vault" >&2
    exit 1
fi

# - deniable hidden vault -
printf 'decoy cover content\n' > "$ROOT/decoy.txt"
printf 'the real secret\n' > "$ROOT/secret.txt"
./build/eyas-crypt seal "$ROOT/decoy.txt" "$ROOT/den.eyas" --pass decoyPW --hidden "$ROOT/secret.txt" --hidden-pass hiddenPW >/dev/null
./build/eyas-crypt info "$ROOT/den.eyas" | grep -q 'policy=deniable'
./build/eyas-crypt open "$ROOT/den.eyas" "$ROOT/den-decoy.txt" --pass decoyPW && cmp "$ROOT/decoy.txt" "$ROOT/den-decoy.txt"
./build/eyas-crypt open "$ROOT/den.eyas" "$ROOT/den-hidden.txt" --pass hiddenPW && cmp "$ROOT/secret.txt" "$ROOT/den-hidden.txt"
if ./build/eyas-crypt open "$ROOT/den.eyas" "$ROOT/den-bad.txt" --pass wrongPW 2>/dev/null; then
    echo "wrong passphrase opened deniable vault" >&2
    exit 1
fi
# a decoy-only deniable vault must be the same size as a decoy+hidden one
./build/eyas-crypt seal "$ROOT/decoy.txt" "$ROOT/den-solo.eyas" --deniable --pass decoyPW >/dev/null
if [ "$(wc -c < "$ROOT/den.eyas")" != "$(wc -c < "$ROOT/den-solo.eyas")" ]; then
    echo "deniable vaults leak hidden-payload presence via size" >&2
    exit 1
fi

echo "smoke ok"
