#!/usr/bin/env bash
# install.sh — Install the codebase-audit and/or firmware-audit skills for
# GitHub Copilot Chat, Claude Code CLI, and/or OpenAI Codex CLI.
#
# Design: each (skill, client) pair gets its OWN self-contained copy. For a
# skill <s>:
#   - Copilot install root: ~/.copilot/skills/<s>/
#   - Claude install root:  ~/.claude/skills/<s>/
#       launchers:          ~/.claude/commands/<s>.md
#                           ~/.claude/commands/<s>/*.md
#   - Codex install roots:  ~/.agents/skills/<s>/ and
#                           ${CODEX_HOME:-~/.codex}/skills/<s>/
#
# The operator-facing surface (SKILL.md, references/, workflows/ if any, and the
# Claude launchers) comes from the skill's surface dir — the repo root for
# codebase-audit, <root>/firmware-audit/ for firmware-audit. The shared audit.py
# + audit_core/ always come from the repo root (the core dir), so both skills
# vendor an identical core. The surface files carry the literal string
# __SKILL_DIR__; install.sh sed-substitutes it with that install's own SKILL_DIR
# on copy, so every `python3 __SKILL_DIR__/audit.py ...` command resolves to that
# skill's own copy. audit.py / audit_core are copied verbatim (never
# substituted). Installing one (skill, client) pair does not touch the others.
#
# Usage:
#   ./install.sh                          # all skills, all clients
#   ./install.sh copilot                  # only Copilot Chat
#   ./install.sh claude                   # only Claude Code CLI
#   ./install.sh codex                    # only Codex CLI
#   ./install.sh --skill firmware-audit   # only the firmware-audit skill
#   ./install.sh --skill codebase-audit   # only the codebase-audit skill
#   ./install.sh --skill all              # both skills (default)
#   ./install.sh --insiders               # use VS Code Insiders paths
#   ./install.sh --uninstall              # remove the selected skills' launchers
#                                         # AND their skill install dirs

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# SCRIPT_DIR is the repo-root checkout: the core dir (audit.py + audit_core/) and
# the codebase-audit surface dir. CORE_DIR names it where intent is "the core".
CORE_DIR="${SCRIPT_DIR}"

# ---- args ----
TARGETS=()
SKILLS=()
INSIDERS=0
UNINSTALL=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    copilot|claude|codex|all) TARGETS+=("$1"); shift ;;
    --skill)
      [[ $# -ge 2 ]] || { echo "ERROR: --skill needs a value (codebase-audit | firmware-audit | all)" >&2; exit 1; }
      case "$2" in
        codebase-audit|firmware-audit|all) SKILLS+=("$2") ;;
        *) echo "ERROR: unknown skill: $2 (use codebase-audit | firmware-audit | all)" >&2; exit 1 ;;
      esac
      shift 2 ;;
    --insiders) INSIDERS=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) awk 'NR>1 && /^#/{sub(/^# ?/,""); print} /^set /{exit}' "$0"; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

if [[ ${#TARGETS[@]} -eq 0 ]] || [[ " ${TARGETS[*]} " == *" all "* ]]; then
  TARGETS=(copilot claude codex)
fi

if [[ ${#SKILLS[@]} -eq 0 ]] || [[ " ${SKILLS[*]} " == *" all "* ]]; then
  SKILLS=(codebase-audit firmware-audit)
fi

# ---- per-client paths (the command dir is skill-independent) ----
CLAUDE_COMMANDS_DIR="${HOME}/.claude/commands"

detect_copilot_prompts_dir() {
  local code_dir
  if [[ "${INSIDERS}" == "1" ]]; then code_dir="Code - Insiders"; else code_dir="Code"; fi

  if [[ -d "${HOME}/.vscode-server/data/User" ]]; then
    echo "${HOME}/.vscode-server/data/User/prompts"; return
  fi
  if [[ "${INSIDERS}" == "1" && -d "${HOME}/.vscode-server-insiders/data/User" ]]; then
    echo "${HOME}/.vscode-server-insiders/data/User/prompts"; return
  fi
  case "$(uname -s)" in
    Darwin) echo "${HOME}/Library/Application Support/${code_dir}/User/prompts" ;;
    Linux)  echo "${HOME}/.config/${code_dir}/User/prompts" ;;
    MINGW*|MSYS*|CYGWIN*) echo "${APPDATA:-${HOME}/AppData/Roaming}/${code_dir}/User/prompts" ;;
    *) echo "${HOME}/.config/${code_dir}/User/prompts" ;;
  esac
}

COPILOT_PROMPTS_DIR="$(detect_copilot_prompts_dir)"

# ---- sanity ----
if [[ ! -f "${CORE_DIR}/SKILL.md" ]]; then
  echo "ERROR: SKILL.md not found next to install.sh." >&2
  exit 1
fi

# Resolve the surface dir (SKILL.md, references/, workflows/, launchers) for a
# skill. codebase-audit's surface IS the repo root; firmware-audit's surface is
# the firmware-audit/ subtree. The core (audit.py + audit_core/) is always
# CORE_DIR regardless.
surface_dir_for() {
  case "$1" in
    firmware-audit) echo "${CORE_DIR}/firmware-audit" ;;
    *)              echo "${CORE_DIR}" ;;
  esac
}

# ---- helpers ----

# install_skill_files <surface_dir> <core_dir> <dest>
# Copy the surface (SKILL.md + workflows/ + references/) from <surface_dir> and
# the shared audit.py + audit_core/ from <core_dir> into <dest>, substituting
# __SKILL_DIR__ in the surface as it goes. Refuses outright if <dest> IS the
# repo-root checkout (<core_dir>) — see the error text below.
install_skill_files() {
  local surface_dir="$1" core_dir="$2" target="$3"
  mkdir -p "${target}"
  local abs_target sub src rel dst
  abs_target="$(cd "${target}" && pwd -P)"
  if [[ "${core_dir}" == "${abs_target}" ]]; then
    echo "ERROR: the source directory IS the install directory:" >&2
    echo "         ${abs_target}" >&2
    echo "       The skill content cannot be substituted in place. Substituting" >&2
    echo "       __SKILL_DIR__ here would rewrite the files of this git checkout," >&2
    echo "       and skipping the substitution leaves the __SKILL_DIR__ sentinel" >&2
    echo "       in the installed skill, so every 'python3 __SKILL_DIR__/audit.py'" >&2
    echo "       command would fail. A tree cannot be both a source checkout and" >&2
    echo "       an install target." >&2
    echo "       Install from a separate checkout into a different directory:" >&2
    echo "         git clone <repo> ~/src/codebase-audit" >&2
    echo "         ~/src/codebase-audit/install.sh" >&2
    exit 1
  fi
  echo "  Copying skill content -> ${target}"
  # SKILL.md, workflows/ and references/ all carry `python3 __SKILL_DIR__/audit.py`
  # commands, so they go through the same substitution as the Claude launchers.
  # A plain `cp` here ships the sentinel literally and every audit.py command in
  # the installed skill fails with "can't open file '.../__SKILL_DIR__/audit.py'".
  substitute_file "${surface_dir}/SKILL.md" "${target}/SKILL.md" "${abs_target}"
  # audit.py + audit_core/ come from the core dir (repo root) and are copied
  # verbatim — they must NOT be substituted.
  cp -f "${core_dir}/audit.py" "${target}/audit.py"
  # Remove before copying, so a file deleted from the repo does not linger in
  # an installed tree forever. install.ps1 already does this; this is the
  # matching behaviour. The clone-in-place guard above has already run, so
  # ${target} is never this checkout.
  for sub in workflows references; do
    rm -rf "${target:?}/${sub}"
  done
  for sub in workflows references; do
    # firmware-audit ships no workflows/; skip gracefully when the surface
    # lacks the subtree.
    [[ -d "${surface_dir}/${sub}" ]] || continue
    # Recursive, so references/briefs/ is covered too.
    while IFS= read -r src; do
      rel="${src#${surface_dir}/${sub}/}"
      dst="${target}/${sub}/${rel}"
      mkdir -p "$(dirname "${dst}")"
      case "${src}" in
        *.md|*.txt) substitute_file "${src}" "${dst}" "${abs_target}" ;;
        *)          cp -f "${src}" "${dst}" ;;
      esac
    done < <(find "${surface_dir}/${sub}" -type f -print)
  done
  # audit_core carries .py and .sql; copy the package wholesale minus caches.
  rm -rf "${target}/audit_core"
  mkdir -p "${target}/audit_core"
  cp -Rf "${core_dir}/audit_core/." "${target}/audit_core/"
  find "${target}/audit_core" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true

  # The install is not complete until the tool runs from where it landed.
  local pyver
  pyver="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo "none")"
  if ! python3 "${target}/audit.py" selftest >/dev/null 2>&1; then
    echo "ERROR: audit.py selftest failed in ${target} — the install is incomplete." >&2
    echo "       python3 on PATH is ${pyver}; this skill requires 3.10 or newer." >&2
    echo "       Install a newer python3, or put one earlier on PATH, then re-run." >&2
    exit 1
  fi
  echo "  selftest OK"
}

# sed-substitute __SKILL_DIR__ in $1 with $3, write result to $2, quietly.
# Uses '|' as sed delimiter so '/' in paths needs no escaping. sed is
# line-content oriented, so a CRLF file stays CRLF: only the trailing \n is
# consumed and re-emitted, and the \r travels inside the line.
substitute_file() {
  local src="$1" dst="$2" skill_dir="$3"
  mkdir -p "$(dirname "${dst}")"
  sed -e "s|__SKILL_DIR__|${skill_dir}|g" "${src}" > "${dst}"
}

# substitute_file, plus the per-file line the launcher install prints.
copy_template() {
  substitute_file "$1" "$2" "$3"
  echo "  -> $2"
}

# install_copilot <skill> <surface_dir> <copilot_skill_dir>
install_copilot() {
  local skill="$1" surface_dir="$2" copilot_dir="$3"
  echo "[copilot] ${skill}"
  echo "  skill dir:     ${copilot_dir}"
  install_skill_files "${surface_dir}" "${CORE_DIR}" "${copilot_dir}"
  # Silently remove any legacy launcher left by older installs so it can't
  # produce a duplicate `/${skill}` autocomplete entry.
  rm -f "${COPILOT_PROMPTS_DIR}/${skill}.prompt.md"
}

# install_claude <skill> <surface_dir> <claude_skill_dir>
install_claude() {
  local skill="$1" surface_dir="$2" claude_dir="$3" f
  echo "[claude] ${skill}"
  echo "  skill dir:     ${claude_dir}"
  echo "  commands dir:  ${CLAUDE_COMMANDS_DIR}"
  install_skill_files "${surface_dir}" "${CORE_DIR}" "${claude_dir}"
  # Top-level command
  if [[ -f "${surface_dir}/claude/commands/${skill}.md" ]]; then
    copy_template \
      "${surface_dir}/claude/commands/${skill}.md" \
      "${CLAUDE_COMMANDS_DIR}/${skill}.md" \
      "${claude_dir}"
  fi
  # Namespaced sub-commands
  if [[ -d "${surface_dir}/claude/commands/${skill}" ]]; then
    for f in "${surface_dir}/claude/commands/${skill}/"*.md; do
      [[ -e "$f" ]] || continue
      copy_template "$f" \
        "${CLAUDE_COMMANDS_DIR}/${skill}/$(basename "$f")" \
        "${claude_dir}"
    done
  fi
}

# install_codex <skill> <surface_dir> <codex_skill_dir...>
install_codex() {
  local skill="$1" surface_dir="$2"
  shift 2
  echo "[codex] ${skill}"
  # Codex auto-discovers the skill by its SKILL.md description — no launcher.
  local d
  for d in "$@"; do
    echo "  skill dir:     ${d}"
    install_skill_files "${surface_dir}" "${CORE_DIR}" "${d}"
  done
}

uninstall_skill_dir() {
  local target="$1"
  local abs_target
  abs_target="$(cd "${target}" 2>/dev/null && pwd -P || echo /nonexistent)"
  if [[ -d "${target}" && "${CORE_DIR}" != "${abs_target}" ]]; then
    echo "  removing ${target}"
    rm -rf "${target}"
  else
    echo "  (skipping ${target} — does not exist OR is the source dir)"
  fi
}

# uninstall_copilot <skill> <copilot_skill_dir>
uninstall_copilot() {
  local skill="$1" copilot_dir="$2"
  echo "[copilot] ${skill} uninstalling"
  rm -f "${COPILOT_PROMPTS_DIR}/${skill}.prompt.md"
  uninstall_skill_dir "${copilot_dir}"
}

# uninstall_claude <skill> <claude_skill_dir>
uninstall_claude() {
  local skill="$1" claude_dir="$2"
  echo "[claude] ${skill} uninstalling"
  rm -f "${CLAUDE_COMMANDS_DIR}/${skill}.md"
  rm -rf "${CLAUDE_COMMANDS_DIR}/${skill}"
  uninstall_skill_dir "${claude_dir}"
}

# uninstall_codex <skill> <codex_skill_dir...>
uninstall_codex() {
  local skill="$1"
  shift
  echo "[codex] ${skill} uninstalling"
  local d
  for d in "$@"; do
    uninstall_skill_dir "${d}"
  done
}

# ---- run ----
echo "Skills:  ${SKILLS[*]}"
echo "Targets: ${TARGETS[*]}"
echo

for skill in "${SKILLS[@]}"; do
  surface_dir="$(surface_dir_for "${skill}")"
  copilot_skill_dir="${HOME}/.copilot/skills/${skill}"
  claude_skill_dir="${HOME}/.claude/skills/${skill}"
  codex_skill_dirs=(
    "${HOME}/.agents/skills/${skill}"
    "${CODEX_HOME:-${HOME}/.codex}/skills/${skill}"
  )

  if [[ "${UNINSTALL}" == "1" ]]; then
    for t in "${TARGETS[@]}"; do
      case "$t" in
        copilot) uninstall_copilot "${skill}" "${copilot_skill_dir}" ;;
        claude)  uninstall_claude "${skill}" "${claude_skill_dir}" ;;
        codex)   uninstall_codex "${skill}" "${codex_skill_dirs[@]}" ;;
      esac
    done
    continue
  fi

  for t in "${TARGETS[@]}"; do
    case "$t" in
      copilot) install_copilot "${skill}" "${surface_dir}" "${copilot_skill_dir}" ;;
      claude)  install_claude "${skill}" "${surface_dir}" "${claude_skill_dir}" ;;
      codex)   install_codex "${skill}" "${surface_dir}" "${codex_skill_dirs[@]}" ;;
    esac
  done
done

if [[ "${UNINSTALL}" == "1" ]]; then
  echo
  echo "Uninstalled."
  exit 0
fi

echo
echo "Done."
for skill in "${SKILLS[@]}"; do
  case "${skill}" in
    firmware-audit) phases="qualify (or acquire / triage / diff / surface / hunt / fpcheck / chain / dive / decide / firmware-report)" ;;
    *)              phases="recon (or deploy / audit / fpcheck / verify <ids> / report)" ;;
  esac
  codex_skill_dirs=(
    "${HOME}/.agents/skills/${skill}"
    "${CODEX_HOME:-${HOME}/.codex}/skills/${skill}"
  )
  if [[ " ${TARGETS[*]} " == *" copilot "* ]]; then
    echo
    echo "Copilot Chat (VS Code) [${skill}]: reload window, then type '/${skill}'."
    echo "  For a specific phase: '/${skill} ${phases}'."
  fi
  if [[ " ${TARGETS[*]} " == *" claude "* ]]; then
    echo
    echo "Claude Code CLI [${skill}]: '/${skill}', then phase subcommands, e.g."
    echo "  '/${skill}:${phases%% *}'."
    echo "  (Claude also auto-loads the skill from ~/.claude/skills/${skill}/ based"
    echo "   on description triggers.)"
  fi
  if [[ " ${TARGETS[*]} " == *" codex "* ]]; then
    echo
    echo "Codex CLI [${skill}]: restart Codex (or run '/skills'), then invoke with '\$${skill}'."
    echo "  For a specific phase, pass it as an argument: '\$${skill} ${phases}'."
    echo "  Codex also auto-loads the skill from either of these dirs:"
    for d in "${codex_skill_dirs[@]}"; do
      echo "    ${d}/"
    done
  fi
done
