#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root"
fail=0
note() {
  printf '  x %s\n' "$1" >&2
  fail=1
}

tracked_plaintext="$({ git ls-files -z || true; } | tr '\0' '\n' \
  | grep -E '(^|/)\.env$|(^|/)\.env\.[^/]*$|(^|/)env/dec/' \
  | grep -vE '\.(example|sample|template)$' || true)"
if [[ -n "$tracked_plaintext" ]]; then
  note 'plaintext environment files are tracked'
  printf '%s\n' "$tracked_plaintext" | sed 's/^/      /'
else
  printf '  ok no plaintext environment files tracked\n'
fi

forced="$({ git ls-files -z || true; } | tr '\0' '\n' \
  | git check-ignore --no-index --stdin 2>/dev/null \
  | grep -E '(^|/)env/|\.env$|\.age-?key$|(^|/)keys\.txt$|sops-private' || true)"
if [[ -n "$forced" ]]; then
  note 'secret-shaped files were force-added past .gitignore'
  printf '%s\n' "$forced" | sed 's/^/      /'
else
  printf '  ok no secret-shaped file bypasses .gitignore\n'
fi

private_keys="$({ git ls-files -z || true; } | tr '\0' '\n' \
  | grep -E '\.(agekey|age-key)$|(^|/)keys\.txt$|AGE-SECRET-KEY' || true)"
if [[ -n "$private_keys" ]]; then
  note 'possible private key material is tracked'
  printf '%s\n' "$private_keys" | sed 's/^/      /'
else
  printf '  ok no age private keys tracked\n'
fi

for rule in '.env' '*.env' '**/*.env' 'env/dec/'; do
  if grep -qxF "$rule" .gitignore 2>/dev/null; then
    printf '  ok .gitignore contains %s\n' "$rule"
  else
    note "missing .gitignore rule: $rule"
  fi
done

shopt -s nullglob
ciphertexts=(env/enc/*.env.enc)
if [[ ${#ciphertexts[@]} -eq 0 ]]; then
  printf '  ok no encrypted environments are defined yet\n'
else
  for file in "${ciphertexts[@]}"; do
    if ! grep -q 'ENC\[AES256_GCM' "$file"; then
      note "$file is not SOPS-encrypted"
      continue
    fi
    grep -q '^sops_mac=' "$file" || note "$file has no SOPS MAC"
    recipients="$(grep -c 'map_recipient' "$file" || true)"
    if [[ "$recipients" -lt 2 ]]; then
      note "$file has $recipients recipient(s); at least two are required"
    else
      printf '  ok %s is encrypted with %s recipients\n' "$file" "$recipients"
    fi
  done
fi

if [[ "$fail" -ne 0 ]]; then
  printf 'env-check FAILED\n' >&2
  exit 1
fi
printf 'env-check PASSED\n'
