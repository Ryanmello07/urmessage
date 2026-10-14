#!/usr/bin/env bash
# THROWAWAY (ruling R31): the deny table, with the readers started from THIS bash (Git Bash, the
# shell fork-ci's windows leg and test.sh run under). icacls is started from bash too, with MSYS
# path conversion off so its /deny and /remove:d are not rewritten into paths.
# Usage: bash table.sh <denyprobe.exe>
probe=$1
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
me=$(whoami | tr -d '\r')
usertemp=$(cygpath -w "${TMP:-/tmp}")
for location in "user temp|$usertemp" "RUNNER_TEMP|$RUNNER_TEMP"; do
  label=${location%%|*}
  base=${location#*|}
  for mask in '(R)' '(RD)'; do
    dir="$base\\denyprobe-$RANDOM$RANDOM"
    mkdir -p "$(cygpath -u "$dir")"
    file="$dir\\epoch"
    printf 'the octets of an epoch state' > "$(cygpath -u "$file")"
    echo "=== bash | $label | $mask | $file"
    icacls "$file" /deny "$me:$mask" > /dev/null
    echo "  icacls listing:"
    icacls "$file" | tr -d '\r' | sed 's/^/    /'
    "$probe" "$file"
    pwsh -NoProfile -Command "try { Get-Content -Path '$file' -ErrorAction Stop | Out-Null; 'READ (no error)' } catch { \$_.Exception.Message }" | tr -d '\r' | sed 's/^/  Get-Content (pwsh started from bash): /'
    icacls "$file" /remove:d "$me" > /dev/null
    rm -rf "$(cygpath -u "$dir")"
  done
done
