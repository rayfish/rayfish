#!/usr/bin/env bash
# A/B benchmark: baseline (HEAD) vs the uncommitted zero-copy forward-path change.
#
# The optimization lives in the working tree (src/{tun,forward,daemon}.rs); HEAD
# still has the original Vec<u8>/copy_from_slice path. We bench BOTH on the SAME
# provisioned pair, back-to-back, so the only variable is the code:
#   1. provision (if needed)
#   2. `git stash` the src changes -> deploy + bench BASELINE
#   3. `git stash pop`             -> deploy + bench NEW
# Each half is a full clean run.sh (resets daemon state, rebuilds the network).
#
# Untracked (this file, results/, .servers) survives the stash; run.sh is
# committed so it survives too. Results saved to results/AB-{baseline,new}.md.
set -uo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
ITERS="${ITERATIONS:-5}"
DUR="${DURATION:-10}"

cd "$ROOT"

# 1. provision -----------------------------------------------------------------
if [[ ! -f "$DIR/.servers" ]]; then
  echo "== provisioning =="
  ZONE="${ZONE:-fr-par-1}" TYPE="${TYPE:-DEV1-S}" bash "$DIR/provision.sh" || exit 1
fi

latest_md(){ ls -t "$DIR"/results/*.md 2>/dev/null | head -1; }

# 2. baseline ------------------------------------------------------------------
STASHED=0
if ! git diff --quiet -- src/; then
  echo "== stashing optimization (baseline = HEAD) =="
  git stash push -m "bench-ab optimization" -- src/ || exit 1
  STASHED=1
fi

echo "== BASELINE run =="
ITERATIONS="$ITERS" DURATION="$DUR" bash "$DIR/run.sh"
BASE_MD="$(latest_md)"
[[ -n "$BASE_MD" ]] && cp "$BASE_MD" "$DIR/results/AB-baseline.md"

# 3. restore optimization, then bench new --------------------------------------
if [[ "$STASHED" == 1 ]]; then
  echo "== restoring optimization (new) =="
  git stash pop || { echo "STASH POP FAILED — working tree may be missing the optimization"; exit 1; }
fi

echo "== NEW run =="
ITERATIONS="$ITERS" DURATION="$DUR" KEEP_STATE=0 bash "$DIR/run.sh"
NEW_MD="$(latest_md)"
[[ -n "$NEW_MD" ]] && cp "$NEW_MD" "$DIR/results/AB-new.md"

# 4. summary -------------------------------------------------------------------
echo
echo "######################## BASELINE (HEAD) ########################"
cat "$DIR/results/AB-baseline.md" 2>/dev/null
echo
echo "######################## NEW (zero-copy) #######################"
cat "$DIR/results/AB-new.md" 2>/dev/null
echo
echo "Saved: $DIR/results/AB-baseline.md  +  AB-new.md"
echo "Tear down: tests/bench/teardown.sh"
