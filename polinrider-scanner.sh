#!/bin/bash
#
# PolinRider Malware Scanner v2.0
# https://opensourcemalware.com
#
# Scans local git repositories for evidence of PolinRider malware infection.
#
# PolinRider appends obfuscated JS payloads to project files and uses
# temp_auto_push.bat to amend commits and force-push to GitHub. The campaign
# has multiple injection vectors (config files, fake .woff/.woff2 fonts,
# .vscode/tasks.json curl-to-shell, malicious npm deps) and two active
# obfuscator variants (rmcej%otb% and Cot%3t=shtP).
#
# v2.0 scans file CONTENT regardless of file type/extension, so payloads
# hidden in binary assets like .woff2 fonts are caught. Detection logic
# mirrors the published multi-variant `polinrider_payload` YARA rule,
# including the corroboration requirements for weaker markers.
#
# Usage:
#   ./polinrider-scanner.sh                        # Scan current directory (thorough)
#   ./polinrider-scanner.sh /path/to/projects      # Scan specific directory
#   ./polinrider-scanner.sh --verbose /path        # Verbose output
#   ./polinrider-scanner.sh --fast /path           # Quick scan (known config files only)
#   ./polinrider-scanner.sh --exclude dist /path   # Skip a directory (repeatable)
#
# Exit codes:
#   0 - No infections found
#   1 - Infections found
#   2 - Error (invalid path, etc.)

set -u

VERSION="2.0"
VERBOSE=0
FAST=0
SCAN_DIR=""
EXCLUDES=()

# --- Indicators of Compromise (mirror the README / YARA rule) ----------------

# Strong content markers: high-specificity, flag a file on their own.
STRONG_ARGS=(
    -e 'rmcej%otb%'
    -e 'Cot%3t=shtP'
    -e 'default-configuration.vercel.app'
    -e 'vscode-settings-bootstrap.vercel.app'
    -e 'vscode-settings-config.vercel.app'
    -e 'vscode-bootstrapper.vercel.app'
    -e 'vscode-load-config.vercel.app'
    -e '260120.vercel.app'
    -e 'e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9'
    -e '2[gWfGj;<:-93Z^C'
    -e 'm6:tTh^D)cBz?NM]'
    -e 'TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP'
    -e 'TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG'
    -e '0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e'
    -e '0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3'
)

# Vercel C2 bootstrap subdomains (for labeling).
C2_ARGS=(
    -e 'default-configuration.vercel.app'
    -e 'vscode-settings-bootstrap.vercel.app'
    -e 'vscode-settings-config.vercel.app'
    -e 'vscode-bootstrapper.vercel.app'
    -e 'vscode-load-config.vercel.app'
    -e '260120.vercel.app'
)

# Blockchain dead-drop C2 + XOR keys (for labeling).
BLOCKCHAIN_ARGS=(
    -e '2[gWfGj;<:-93Z^C'
    -e 'm6:tTh^D)cBz?NM]'
    -e 'TMfKQEd7TJJa5xNZJZ2Lep838vrzrs7mAP'
    -e 'TXfxHUet9pJVU1BgVkBAbrES4YUc1nGzcG'
    -e '0xbe037400670fbf1c32364f762975908dc43eeb38759263e7dfcdabc76380811e'
    -e '0x3f0e5781d0855fb460661ac63257376db1941b2bb522499e4757ecb3ebd5dce3'
)

UUID='e9b53a7c-2342-4b15-b02d-bd8b8f6a03f9'

# Weak markers: only flag when corroborated (see scan_content).
GLOBAL_BANG="global['!']"
GLOBAL_V="global['_V']"
GLOBAL_R="global['r'] = require"
GLOBAL_M="global['m'] = module"
SEEDS_RE='(2857687|2667686|1111436|3896884)'

# Known malicious npm package names (checked inside package.json files).
NPM_NAMES=(
    'tailwindcss-style-animate'
    'tailwind-mainanimation'
    'tailwind-autoanimation'
    'tailwind-animationbased'
    'tailwindcss-typography-style'
    'tailwindcss-style-modify'
    'tailwindcss-animate-style'
)
NPM_ARGS=()
for _n in "${NPM_NAMES[@]}"; do NPM_ARGS+=( -e "$_n" ); done

# Config files checked in --fast mode (root of each repo).
CONFIG_FILES="postcss.config.mjs postcss.config.js postcss.config.ts \
tailwind.config.js tailwind.config.mjs tailwind.config.ts \
eslint.config.mjs eslint.config.js next.config.mjs next.config.js next.config.ts \
vite.config.js vite.config.mjs vite.config.ts webpack.config.js gridsome.config.js \
vue.config.js truffle.js astro.config.mjs babel.config.js jest.config.js \
svelte.config.js nuxt.config.js nuxt.config.ts rollup.config.js App.js index.js"

# Colors (disabled if not a terminal)
RED=""
GREEN=""
YELLOW=""
CYAN=""
BOLD=""
RESET=""

if [ -t 1 ]; then
    RED='\033[0;31m'
    GREEN='\033[0;32m'
    YELLOW='\033[1;33m'
    CYAN='\033[0;36m'
    BOLD='\033[1m'
    RESET='\033[0m'
fi

# Counters
TOTAL_REPOS=0
INFECTED_REPOS=0

# Per-repo finding state (reset at the top of scan_repo)
F_FINDINGS=""
F_COUNT=0
F_SEEN=""

print_banner() {
    printf "\n"
    printf "${BOLD}========================================${RESET}\n"
    printf "${BOLD}  PolinRider Malware Scanner v%s${RESET}\n" "$VERSION"
    printf "${BOLD}  https://opensourcemalware.com${RESET}\n"
    printf "${BOLD}========================================${RESET}\n"
    printf "\n"
}

print_usage() {
    printf "Usage: %s [options] [directory]\n" "$0"
    printf "\n"
    printf "Scans git repositories for PolinRider malware artifacts.\n"
    printf "Content is scanned regardless of file type, so payloads hidden in\n"
    printf "binary assets (e.g. fake .woff/.woff2 fonts) are detected.\n"
    printf "\n"
    printf "Options:\n"
    printf "  --verbose        Show detailed output for each repository\n"
    printf "  --fast           Quick scan: only known config files + artifacts\n"
    printf "  --exclude <dir>  Skip directories matching <dir> (repeatable)\n"
    printf "  --js-all         Deprecated alias for the default (thorough) scan\n"
    printf "  --help           Show this help message\n"
    printf "\n"
    printf "Note: because this tool searches file content for malware\n"
    printf "signatures, pointing it at the PolinRider repo itself (or any copy\n"
    printf "of these signatures) will flag the documentation as 'infected'.\n"
    printf "Use --exclude to skip such directories.\n"
    printf "\n"
    printf "Examples:\n"
    printf "  %s                          # Scan current directory\n" "$0"
    printf "  %s /path/to/projects        # Scan specific directory\n" "$0"
    printf "  %s --verbose ~/projects     # Verbose scan\n" "$0"
    printf "  %s --fast ~/projects        # Quick config-file scan\n" "$0"
    printf "  %s --exclude dist ~/proj    # Skip dist/ directories\n" "$0"
}

log_verbose() {
    if [ "$VERBOSE" -eq 1 ]; then
        printf "  ${CYAN}[verbose]${RESET} %s\n" "$1"
    fi
}

# Record a finding, deduplicated by path so the same file isn't listed twice.
add_finding() {
    local relpath="$1" msg="$2" color="${3:-$RED}"
    case "
${F_SEEN}
" in
        *"
${relpath}
"*) return 0 ;;
    esac
    F_SEEN="${F_SEEN}
${relpath}"
    F_FINDINGS="${F_FINDINGS}  ${color}-${RESET} ${BOLD}${relpath}${RESET}: ${msg}\n"
    F_COUNT=$((F_COUNT + 1))
}

# Identify which IOC a flagged file matched, for a human-readable label.
classify_payload() {
    local f="$1"
    if grep -qaF 'rmcej%otb%' "$f" 2>/dev/null; then
        printf 'PolinRider payload detected (variant 1: rmcej%%otb%%)'
    elif grep -qaF 'Cot%3t=shtP' "$f" 2>/dev/null; then
        printf 'PolinRider payload detected (variant 2: Cot%%3t=shtP)'
    elif grep -qaF "${C2_ARGS[@]}" "$f" 2>/dev/null; then
        printf 'C2 endpoint reference (Vercel TasksJacker bootstrap server)'
    elif grep -qaF "$UUID" "$f" 2>/dev/null; then
        printf 'StakingGame fake-interview template UUID'
    elif grep -qaF "${BLOCKCHAIN_ARGS[@]}" "$f" 2>/dev/null; then
        printf 'Blockchain dead-drop C2 IOC (TRON/Aptos address or XOR key)'
    else
        printf 'PolinRider payload detected (obfuscator markers)'
    fi
}

# Build a NUL-delimited list of files to content-scan into $1.
build_file_list() {
    local repo_dir="$1" out="$2"
    : > "$out"
    if [ "$FAST" -eq 1 ]; then
        local old_ifs="$IFS"
        IFS=' '
        local cf
        for cf in $CONFIG_FILES; do
            [ -f "${repo_dir}/${cf}" ] && printf '%s\0' "${repo_dir}/${cf}" >> "$out"
        done
        IFS="$old_ifs"
    else
        local args=( "$repo_dir" -name .git -prune -o )
        local ex
        for ex in ${EXCLUDES[@]+"${EXCLUDES[@]}"}; do
            args+=( -path "*/${ex}/*" -prune -o -name "$ex" -prune -o )
        done
        args+=( -type f -print0 )
        find "${args[@]}" 2>/dev/null > "$out"
    fi
}

# Content-scan the file list in $1 for strong markers + corroborated weak markers.
scan_content() {
    local repo_dir="$1" listfile="$2"
    [ -s "$listfile" ] || return 0
    local f

    # Strong markers — flag on their own.
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        add_finding "${f#${repo_dir}/}" "$(classify_payload "$f")"
    done <<EOF
$(xargs -0 grep -alF "${STRONG_ARGS[@]}" < "$listfile" 2>/dev/null)
EOF

    # Corroboration: global['!'] + (seed 2857687 or decoder _$_1e42)
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        if grep -qaF -e '2857687' -e '_$_1e42' "$f" 2>/dev/null; then
            add_finding "${f#${repo_dir}/}" "PolinRider payload detected (corroborated variant-1 markers)"
        fi
    done <<EOF
$(xargs -0 grep -alF -e "$GLOBAL_BANG" < "$listfile" 2>/dev/null)
EOF

    # Corroboration: global['_V'] + (seed 1111436 or decoder MDy)
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        if grep -qaF -e '1111436' -e 'MDy' "$f" 2>/dev/null; then
            add_finding "${f#${repo_dir}/}" "PolinRider payload detected (corroborated variant-2 markers)"
        fi
    done <<EOF
$(xargs -0 grep -alF -e "$GLOBAL_V" < "$listfile" 2>/dev/null)
EOF

    # Corroboration: global['r']=require + global['m']=module + any shuffle seed
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        if grep -qaF -e "$GLOBAL_M" "$f" 2>/dev/null \
           && grep -qaE "$SEEDS_RE" "$f" 2>/dev/null; then
            add_finding "${f#${repo_dir}/}" "PolinRider payload detected (corroborated require/module + seed)"
        fi
    done <<EOF
$(xargs -0 grep -alF -e "$GLOBAL_R" < "$listfile" 2>/dev/null)
EOF
}

# Flag malicious .vscode/tasks.json files (TasksJacker curl-to-shell vector).
scan_tasks_json() {
    local repo_dir="$1" f rel
    while IFS= read -r f; do
        [ -n "$f" ] || continue
        rel="${f#${repo_dir}/}"
        if grep -qaF "${C2_ARGS[@]}" "$f" 2>/dev/null \
           || grep -qaF "$UUID" "$f" 2>/dev/null \
           || { grep -qaF 'folderOpen' "$f" 2>/dev/null \
                && grep -qaEi 'curl|wget|\| *bash|\| *sh' "$f" 2>/dev/null; }; then
            add_finding "$rel" "Malicious .vscode/tasks.json (TasksJacker curl-to-shell vector)"
        fi
    done <<EOF
$(find "$repo_dir" -name .git -prune -o -path "*/.vscode/tasks.json" -print 2>/dev/null)
EOF
}

# Flag package.json files referencing known malicious npm packages.
scan_package_json() {
    local repo_dir="$1" listfile="$2" candidate name rel
    : > "$listfile"
    if [ "$FAST" -eq 1 ]; then
        [ -f "${repo_dir}/package.json" ] && printf '%s\0' "${repo_dir}/package.json" > "$listfile"
    else
        local args=( "$repo_dir" -name .git -prune -o )
        local ex
        for ex in ${EXCLUDES[@]+"${EXCLUDES[@]}"}; do
            args+=( -path "*/${ex}/*" -prune -o )
        done
        args+=( -name package.json -print0 )
        find "${args[@]}" 2>/dev/null > "$listfile"
    fi
    [ -s "$listfile" ] || return 0

    while IFS= read -r candidate; do
        [ -n "$candidate" ] || continue
        rel="${candidate#${repo_dir}/}"
        for name in "${NPM_NAMES[@]}"; do
            if grep -qaF "$name" "$candidate" 2>/dev/null; then
                add_finding "$rel" "Malicious npm dependency reference (${name})"
            fi
        done
    done <<EOF
$(xargs -0 grep -alF "${NPM_ARGS[@]}" < "$listfile" 2>/dev/null)
EOF
}

scan_repo() {
    local repo_dir="$1"
    F_FINDINGS=""
    F_COUNT=0
    F_SEEN=""

    log_verbose "Scanning repo: $repo_dir"

    local tmp
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/polinrider-scan.XXXXXX")" || return 0

    # Propagation-script artifact (high-confidence even if payload was cleaned).
    if [ -f "${repo_dir}/temp_auto_push.bat" ]; then
        add_finding "temp_auto_push.bat" "Propagation script found"
    fi
    if [ -f "${repo_dir}/config.bat" ]; then
        add_finding "config.bat" "Hidden orchestrator found"
    fi
    if [ -f "${repo_dir}/.gitignore" ] \
       && grep -qxF "config.bat" "${repo_dir}/.gitignore" 2>/dev/null; then
        add_finding ".gitignore" "config.bat entry injected"
    fi

    # Vector-specific checks.
    scan_tasks_json "$repo_dir"
    scan_package_json "$repo_dir" "${tmp}/pkgs"

    # Content scan (thorough = all files; fast = known config files).
    build_file_list "$repo_dir" "${tmp}/files"
    scan_content "$repo_dir" "${tmp}/files"

    # Git reflog: amended commits are consistent with PolinRider, but only
    # meaningful alongside another finding.
    if [ "$F_COUNT" -gt 0 ] && [ -d "${repo_dir}/.git" ]; then
        if git -C "$repo_dir" reflog 2>/dev/null | grep -q "amend"; then
            log_verbose "Found amend entries in reflog"
            F_FINDINGS="${F_FINDINGS}  ${YELLOW}-${RESET} ${BOLD}git reflog${RESET}: Amended commits found (consistent with PolinRider behavior)\n"
        fi
    fi

    rm -rf "$tmp"

    if [ "$F_COUNT" -gt 0 ]; then
        printf "\n${RED}${BOLD}[INFECTED]${RESET} %s\n" "$repo_dir"
        printf '%b' "$F_FINDINGS"
        INFECTED_REPOS=$((INFECTED_REPOS + 1))
        return 1
    fi

    log_verbose "Clean: $repo_dir"
    return 0
}

# Parse arguments
while [ $# -gt 0 ]; do
    case "$1" in
        --verbose)
            VERBOSE=1
            shift
            ;;
        --fast)
            FAST=1
            shift
            ;;
        --js-all)
            # Deprecated: thorough content scan is now the default.
            FAST=0
            shift
            ;;
        --exclude)
            shift
            if [ $# -eq 0 ]; then
                printf "Error: --exclude requires a directory argument\n" >&2
                exit 2
            fi
            EXCLUDES+=( "$1" )
            shift
            ;;
        --help|-h)
            print_usage
            exit 0
            ;;
        -*)
            printf "Error: Unknown option '%s'\n" "$1" >&2
            print_usage >&2
            exit 2
            ;;
        *)
            if [ -n "$SCAN_DIR" ]; then
                printf "Error: Multiple directories specified\n" >&2
                print_usage >&2
                exit 2
            fi
            SCAN_DIR="$1"
            shift
            ;;
    esac
done

# Default to current directory
if [ -z "$SCAN_DIR" ]; then
    SCAN_DIR="."
fi

# Resolve to absolute, physical path (pwd -P) so a symlinked scan directory
# (e.g. ~/dev -> ~/Documents/dev) is traversed by find instead of skipped.
SCAN_DIR="$(cd "$SCAN_DIR" 2>/dev/null && pwd -P)"
if [ $? -ne 0 ] || [ ! -d "$SCAN_DIR" ]; then
    printf "Error: Directory not found or not accessible: %s\n" "$SCAN_DIR" >&2
    exit 2
fi

print_banner

printf "Scanning: ${BOLD}%s${RESET}" "$SCAN_DIR"
if [ "$FAST" -eq 1 ]; then
    printf " ${CYAN}(fast mode)${RESET}"
fi
printf "\n"

# Find all git repositories
REPO_LIST=""
while IFS= read -r git_dir; do
    [ -n "$git_dir" ] || continue
    repo_dir="$(dirname "$git_dir")"
    REPO_LIST="${REPO_LIST}${repo_dir}
"
    TOTAL_REPOS=$((TOTAL_REPOS + 1))
done <<EOF
$(find "$SCAN_DIR" -name .git -type d 2>/dev/null | sort)
EOF

# Remove trailing newline
REPO_LIST="${REPO_LIST%
}"

if [ "$TOTAL_REPOS" -eq 0 ]; then
    printf "No git repositories found under %s\n" "$SCAN_DIR"
    exit 0
fi

printf "Found ${BOLD}%d${RESET} git repositories...\n" "$TOTAL_REPOS"

# Scan each repo
while IFS= read -r repo; do
    if [ -n "$repo" ]; then
        scan_repo "$repo"
    fi
done <<REPOEOF
$REPO_LIST
REPOEOF

# Print summary
CLEAN_REPOS=$((TOTAL_REPOS - INFECTED_REPOS))
printf "\n"

if [ "$CLEAN_REPOS" -gt 0 ]; then
    printf "${GREEN}${BOLD}[CLEAN]${RESET} %d repositories scanned clean\n" "$CLEAN_REPOS"
fi

printf "\n${BOLD}========================================${RESET}\n"
if [ "$INFECTED_REPOS" -gt 0 ]; then
    printf "  ${RED}${BOLD}RESULTS: %d infected repo(s) found${RESET}\n" "$INFECTED_REPOS"
else
    printf "  ${GREEN}${BOLD}RESULTS: No infections found${RESET}\n"
fi
printf "${BOLD}========================================${RESET}\n"

if [ "$INFECTED_REPOS" -gt 0 ]; then
    printf "\n${BOLD}REMEDIATION STEPS:${RESET}\n"
    printf "1. Remove the obfuscated payload from infected files (config files, and\n"
    printf "   any fake .woff/.woff2 fonts or other assets carrying the marker)\n"
    printf "2. Delete temp_auto_push.bat and config.bat if present\n"
    printf "3. Remove \"config.bat\" from .gitignore\n"
    printf "4. Remove malicious .vscode/tasks.json curl-to-shell tasks\n"
    printf "5. Remove malicious npm dependencies from package.json and reinstall\n"
    printf "6. Check your npm global packages and VS Code extensions for the dropper\n"
    printf "7. Rotate any secrets/tokens exposed during a build, then force-push clean\n"
    printf "8. Report to https://opensourcemalware.com\n"
    printf "\n"
    exit 1
fi

printf "\n"
exit 0
