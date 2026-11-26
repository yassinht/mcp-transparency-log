#!/usr/bin/env bash
# Publishes today's signed tree head to the public repository.
#
# Run after each census, from the systemd unit. A log whose heads never leave
# the machine that produced them is not a transparency log: the whole claim
# rests on other people holding yesterday's head, so publishing is not a
# convenience step, it is the part that makes the rest mean anything.
#
# Failure here must never mark the census failed -- the observations are already
# archived and signed, and GitHub being unreachable at 04:00 is not a reason to
# report that the crawl did not happen. The unit calls this with a leading '-'
# for exactly that reason, and it exits 0 on anything it cannot control.
set -uo pipefail

APP_DIR=${APP_DIR:-/opt/mcp-observatory}
HEADS_DIR="$APP_DIR/heads"
CLONE="$APP_DIR/publish"

log() { echo "publish-head: $*"; }

# A transient GitHub outage is not worth marking a census failed -- the
# observations are archived and signed either way. Being stuck for days is a
# different thing entirely, and it has now happened twice: heads kept being
# signed, pushes kept failing, and nothing anywhere said so. Silence is the
# failure mode that costs the most, because it is indistinguishable from
# working. So: tolerate a bad night, shout after two.
stuck_or_exit() {
  local oldest age days
  oldest=$(git log --format=%ct "@{u}..HEAD" 2>/dev/null | tail -1)
  [ -n "$oldest" ] || exit 0
  age=$(( $(date +%s) - oldest ))
  days=$(( age / 86400 ))
  if [ "$days" -ge 2 ]; then
    log "STUCK: signed heads have been unpublished for ${days} days"
    log "the log is still being written but nobody outside can verify it"
    exit 1   # surfaces as a failed unit in systemctl / journalctl
  fi
  log "will retry tomorrow (unpublished for ${days}d)"
  exit 0
}

# The dated peer index names the commit that carried each night's peer list,
# so it can only be written once that commit exists. It runs before every
# push, not only after a fresh commit: a rebase over a human's push rewrites
# the ids of nights that never left this machine, and the index must follow.
# A failure here costs the index one night, never the heads.
index_dated() {
  [ -x "$APP_DIR/mcpobs" ] || return 0
  if ! "$APP_DIR/mcpobs" peers-dated "$CLONE" >/dev/null 2>>"$APP_DIR/peers-dated.log"; then
    log "dated peer index failed; see peers-dated.log"
    return 0
  fi
  git add docs/data/peers/dated.json 2>/dev/null || return 0
  git diff --cached --quiet && return 0
  git commit -q -m "Index dated peer lists $(date -u +%Y-%m-%d)" || true
}

[ -d "$CLONE/.git" ] || { log "no clone at $CLONE; skipping"; exit 0; }

# Only ever copy the public artefacts. The private key lives beside them and
# must never be handed to a command that pushes to a public remote, so this
# names the files explicitly instead of copying the directory.
mkdir -p "$CLONE/heads"
copied=0
for f in "$HEADS_DIR"/*.txt "$HEADS_DIR/key.pub"; do
  [ -e "$f" ] || continue
  case "$(basename "$f")" in
    key|*.key) continue ;;   # belt and braces
  esac
  if ! cmp -s "$f" "$CLONE/heads/$(basename "$f")"; then
    cp "$f" "$CLONE/heads/"
    copied=$((copied + 1))
  fi
done

cd "$CLONE" || exit 0

# Two writers push to this branch: the server every night, and a human from a
# laptop whenever the code changes. Without a rebase first, the very next
# nightly push is rejected as non-fast-forward and stays rejected until someone
# notices. Rebase rather than merge, so the published head history stays a
# straight line that is easy to audit.
git fetch -q origin 2>/dev/null && git rebase -q origin/HEAD 2>/dev/null || git rebase --abort 2>/dev/null || true

# Unpushed commits from a previous run whose push failed. The earlier version
# exited here whenever there was nothing new to copy, which meant a failed push
# was never retried -- it logged "the next run will retry" and then made that
# impossible. Four days of signed heads sat committed and unpublished.
unpushed=$(git rev-list --count @{u}..HEAD 2>/dev/null || echo 0)

# Checkpoints and witnesses (c2sp.org/tlog-checkpoint, c2sp.org/tlog-witness).
# Every head is also published as a standard checkpoint, signed with the same
# key, so that witnesses run by other people can cosign it. That is the only
# thing that answers "what if the operator shows different readers different
# histories": a witness remembers the last tree it saw and only cosigns trees
# that extend it. This runs after the rebase so a witness a human just added to
# heads/witnesses in the repo is asked tonight, not tomorrow. A witness that is
# down costs one night of its cosignature, never the head: failures are logged
# to witness.log and the publish carries on.
if [ -x "$APP_DIR/mcpobs" ]; then
  if "$APP_DIR/mcpobs" --heads "$HEADS_DIR" --pubkey "$HEADS_DIR/key.pub" checkpoint >>"$APP_DIR/witness.log" 2>&1; then
    if [ -s "$CLONE/heads/witnesses" ]; then
      "$APP_DIR/mcpobs" --data "$APP_DIR/data" --heads "$HEADS_DIR" --pubkey "$HEADS_DIR/key.pub" \
        --witnesses "$CLONE/heads/witnesses" witness >>"$APP_DIR/witness.log" 2>&1 \
        || log "no witness cosigned tonight; see witness.log"
    fi
    # Named explicitly, like the heads above: nothing from this directory but
    # public files ever reaches the clone.
    mkdir -p "$CLONE/heads/checkpoints"
    for f in "$HEADS_DIR"/checkpoints/*.txt; do
      [ -e "$f" ] || continue
      if ! cmp -s "$f" "$CLONE/heads/checkpoints/$(basename "$f")"; then
        cp "$f" "$CLONE/heads/checkpoints/"
        copied=$((copied + 1))
      fi
    done
    for f in checkpoint key.vkey; do
      [ -e "$HEADS_DIR/$f" ] || continue
      if ! cmp -s "$HEADS_DIR/$f" "$CLONE/heads/$f"; then
        cp "$HEADS_DIR/$f" "$CLONE/heads/$f"
        copied=$((copied + 1))
      fi
    done
  else
    log "checkpoint failed; see witness.log"
  fi
fi

# Regenerate the static site data. census.json and the per-day change files are
# small enough to commit every night. servers.json is a few megabytes and every
# row carries a last-seen date, so it rewrites completely every day -- committing
# that nightly would add well over a gigabyte a year to a repository GitHub will
# stop hosting long before then. It goes in weekly instead, which bounds the
# growth without losing anything: the daily change files already carry what moved.
if [ -x "$APP_DIR/mcpobs" ]; then
  if "$APP_DIR/mcpobs" --data "$APP_DIR/data" export "$CLONE/docs" >/dev/null 2>&1; then
    # Leaves are the load-bearing part: without them nobody outside can check
    # a head against anything. They must be staged every run, unlike
    # servers.json below, because a missing day breaks the chain for everyone.
    # Past runs re-export byte-identically, so git stores only the new day.
    git add docs/data/census.json docs/data/changes docs/data/leaves 2>/dev/null || true
    # Per-server pages, badges and the scan summary. The export leaves a file
    # untouched when nothing about that server changed, so on a quiet night
    # this stages a few hundred small files, not thirty thousand.
    git add docs/data/s docs/data/badge docs/data/scan.json docs/data/peers 2>/dev/null || true
    # The rule history: every night since the first census, replayed from the
    # archived bytes. Verdicts are cached by (surface, host) under a key
    # derived from the rule set, so a quiet night costs minutes, and a rule
    # edited tomorrow is re-asked of the whole history. One file, rewritten
    # nightly; the scan page reads it.
    # Two replays appending to one cache file would interleave their lines;
    # if one is already running (a manual replay), tonight's refresh waits
    # for tomorrow rather than racing it.
    if pgrep -f "mcpobs .*--since" >/dev/null 2>&1; then
      log "rule history replay already running; skipped tonight"
    elif "$APP_DIR/mcpobs" --data "$APP_DIR/data" --since 2026-08-30 --scan-json "$CLONE/docs/data/scan-history.json" scan >/dev/null 2>>"$APP_DIR/scan-history.log"; then
      git add docs/data/scan-history.json 2>/dev/null || true
    else
      log "rule history replay failed; see scan-history.log"
    fi
    last=$(git log -1 --format=%ct -- docs/data/servers.json 2>/dev/null || echo 0)
    if [ "$(( ($(date +%s) - last) / 86400 ))" -ge 7 ]; then
      git add docs/data/servers.json 2>/dev/null || true
      log "refreshing servers.json (weekly)"
    else
      git checkout -- docs/data/servers.json 2>/dev/null || true
    fi
    git diff --cached --quiet || copied=$((copied + 1))
  else
    log "site export failed"
  fi
fi

if [ "$copied" -eq 0 ] && [ "$unpushed" -eq 0 ]; then
  log "nothing new to publish"
  exit 0
fi
if [ "$copied" -eq 0 ]; then
  log "no new heads, but $unpushed unpushed commit(s); retrying push"
  index_dated
  if git push -q origin HEAD 2>&1; then
    log "pushed $unpushed pending commit(s)"
    exit 0
  fi
  log "push still failing"
  stuck_or_exit
fi

# Refuse outright if the private key somehow reached the clone. Better to
# publish nothing today than to publish the key once.
if git ls-files --error-unmatch heads/key >/dev/null 2>&1; then
  log "REFUSING: heads/key is tracked in the clone"
  exit 0
fi

git add heads/ || exit 0
if git diff --cached --quiet; then
  log "no staged changes"
  exit 0
fi

size=$(grep -h '^size ' heads/*.txt 2>/dev/null | tail -1 | awk '{print $2}')
git commit -q -m "Publish tree head $(date -u +%Y-%m-%d) (${size:-?} observations)" || exit 0
index_dated

if git push -q origin HEAD 2>&1; then
  log "published $copied file(s), tree size ${size:-?}"
  exit 0
fi
log "push failed; the commit is local"
stuck_or_exit
