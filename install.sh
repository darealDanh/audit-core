#!/usr/bin/env bash
# install.sh — Install the codebase-audit skill for GitHub Copilot Chat,
# Claude Code CLI, and/or OpenAI Codex CLI.
#
# Design: each client gets its OWN self-contained copy of the skill.
#   - Copilot install root: ~/.copilot/skills/codebase-audit/
#   - Claude install root:  ~/.claude/skills/codebase-audit/
#       launchers:          ~/.claude/commands/codebase-audit.md
#                           ~/.claude/commands/codebase-audit/*.md
#   - Codex install root:   ~/.agents/skills/codebase-audit/
#
# Copilot and Codex auto-discover the skill from their skills dir — no launcher
# files. Claude launchers contain the literal string __SKILL_DIR__; install.sh
# sed-substitutes it with the client's own SKILL_DIR so each set of launchers
# points at its own copy. Installing one client does not touch the others.
#
# Usage:
#   ./install.sh                  # install for all clients
#   ./install.sh copilot          # only Copilot Chat
#   ./install.sh claude           # only Claude Code CLI
#   ./install.sh codex            # only Codex CLI
#   ./install.sh --insiders       # use VS Code Insiders paths
#   ./install.sh --uninstall      # remove the selected clients' launchers
#                                 # AND their skill install dirs

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SKILL_NAME="codebase-audit"

# ---- args ----
TARGETS=()
INSIDERS=0
UNINSTALL=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    copilot|claude|codex|all) TARGETS+=("$1"); shift ;;
    --insiders) INSIDERS=1; shift ;;
    --uninstall) UNINSTALL=1; shift ;;
    -h|--help) sed -n '2,24p' "$0"; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

if [[ ${#TARGETS[@]} -eq 0 ]] || [[ " ${TARGETS[*]} " == *" all "* ]]; then
  TARGETS=(copilot claude codex)
fi

# ---- per-client paths ----
COPILOT_SKILL_DIR="${HOME}/.copilot/skills/${SKILL_NAME}"
CLAUDE_SKILL_DIR="${HOME}/.claude/skills/${SKILL_NAME}"
CLAUDE_COMMANDS_DIR="${HOME}/.claude/commands"
# Codex discovers user-authored skills from ~/.agents/skills, but a sibling
# skill installs to $CODEX_HOME/skills instead; install to both since it is
# not knowable from here which one a given Codex build reads.
CODEX_SKILL_DIRS=(
  "${HOME}/.agents/skills/${SKILL_NAME}"
  "${CODEX_HOME:-${HOME}/.codex}/skills/${SKILL_NAME}"
)

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
if [[ ! -f "${SCRIPT_DIR}/SKILL.md" ]]; then
  echo "ERROR: SKILL.md not found next to install.sh." >&2
  exit 1
fi

# ---- helpers ----

# Copy SKILL.md + workflows/ + references/ from SCRIPT_DIR into $1.
# Skips if target is the same as SCRIPT_DIR (e.g. cloned directly into install
# location).
install_skill_files() {
  local target="$1"
  mkdir -p "${target}"
  local abs_target
  abs_target="$(cd "${target}" && pwd -P)"
  if [[ "${SCRIPT_DIR}" == "${abs_target}" ]]; then
    echo "  (source dir IS install dir; skipping skill file copy)"
    return
  fi
  echo "  Copying skill content -> ${target}"
  cp -f "${SCRIPT_DIR}/SKILL.md" "${target}/SKILL.md"
  cp -f "${SCRIPT_DIR}/audit.py" "${target}/audit.py"
  for sub in workflows references; do
    if [[ -d "${SCRIPT_DIR}/${sub}" ]]; then
      mkdir -p "${target}/${sub}"
      cp -Rf "${SCRIPT_DIR}/${sub}/." "${target}/${sub}/"
    fi
  done
  # audit_core carries .py and .sql; copy the package wholesale minus caches.
  rm -rf "${target}/audit_core"
  mkdir -p "${target}/audit_core"
  cp -Rf "${SCRIPT_DIR}/audit_core/." "${target}/audit_core/"
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

# sed-substitute __SKILL_DIR__ in $1 with $3, write result to $2.
# Uses '|' as sed delimiter so '/' in paths needs no escaping.
copy_template() {
  local src="$1" dst="$2" skill_dir="$3"
  mkdir -p "$(dirname "${dst}")"
  sed -e "s|__SKILL_DIR__|${skill_dir}|g" "${src}" > "${dst}"
  echo "  -> ${dst}"
}

install_copilot() {
  echo "[copilot]"
  echo "  skill dir:     ${COPILOT_SKILL_DIR}"
  install_skill_files "${COPILOT_SKILL_DIR}"
  # Silently remove any legacy launcher left by older installs so it can't
  # produce a duplicate `/codebase-audit` autocomplete entry.
  rm -f "${COPILOT_PROMPTS_DIR}/${SKILL_NAME}.prompt.md"
}

install_claude() {
  echo "[claude]"
  echo "  skill dir:     ${CLAUDE_SKILL_DIR}"
  echo "  commands dir:  ${CLAUDE_COMMANDS_DIR}"
  install_skill_files "${CLAUDE_SKILL_DIR}"
  # Top-level command
  if [[ -f "${SCRIPT_DIR}/claude/commands/${SKILL_NAME}.md" ]]; then
    copy_template \
      "${SCRIPT_DIR}/claude/commands/${SKILL_NAME}.md" \
      "${CLAUDE_COMMANDS_DIR}/${SKILL_NAME}.md" \
      "${CLAUDE_SKILL_DIR}"
  fi
  # Namespaced sub-commands
  if [[ -d "${SCRIPT_DIR}/claude/commands/${SKILL_NAME}" ]]; then
    for f in "${SCRIPT_DIR}/claude/commands/${SKILL_NAME}/"*.md; do
      [[ -e "$f" ]] || continue
      copy_template "$f" \
        "${CLAUDE_COMMANDS_DIR}/${SKILL_NAME}/$(basename "$f")" \
        "${CLAUDE_SKILL_DIR}"
    done
  fi
}

install_codex() {
  echo "[codex]"
  # Codex auto-discovers the skill by its SKILL.md description — no launcher.
  for d in "${CODEX_SKILL_DIRS[@]}"; do
    echo "  skill dir:     ${d}"
    install_skill_files "${d}"
  done
}

uninstall_skill_dir() {
  local target="$1"
  local abs_target
  abs_target="$(cd "${target}" 2>/dev/null && pwd -P || echo /nonexistent)"
  if [[ -d "${target}" && "${SCRIPT_DIR}" != "${abs_target}" ]]; then
    echo "  removing ${target}"
    rm -rf "${target}"
  else
    echo "  (skipping ${target} — does not exist OR is the source dir)"
  fi
}

uninstall_copilot() {
  echo "[copilot] uninstalling"
  rm -f "${COPILOT_PROMPTS_DIR}/${SKILL_NAME}.prompt.md"
  uninstall_skill_dir "${COPILOT_SKILL_DIR}"
}

uninstall_claude() {
  echo "[claude] uninstalling"
  rm -f "${CLAUDE_COMMANDS_DIR}/${SKILL_NAME}.md"
  rm -rf "${CLAUDE_COMMANDS_DIR}/${SKILL_NAME}"
  uninstall_skill_dir "${CLAUDE_SKILL_DIR}"
}

uninstall_codex() {
  echo "[codex] uninstalling"
  for d in "${CODEX_SKILL_DIRS[@]}"; do
    uninstall_skill_dir "${d}"
  done
}

# ---- run ----
echo "Targets: ${TARGETS[*]}"
echo

if [[ "${UNINSTALL}" == "1" ]]; then
  for t in "${TARGETS[@]}"; do
    case "$t" in
      copilot) uninstall_copilot ;;
      claude)  uninstall_claude ;;
      codex)   uninstall_codex ;;
    esac
  done
  echo
  echo "Uninstalled."
  exit 0
fi

for t in "${TARGETS[@]}"; do
  case "$t" in
    copilot) install_copilot ;;
    claude)  install_claude ;;
    codex)   install_codex ;;
  esac
done

echo
echo "Done."
if [[ " ${TARGETS[*]} " == *" copilot "* ]]; then
  echo
  echo "Copilot Chat (VS Code): reload window, then type '/codebase-audit'."
  echo "  For a specific phase: '/codebase-audit recon' (or deploy / audit /"
  echo "  fpcheck / verify <ids> / report)."
fi
if [[ " ${TARGETS[*]} " == *" claude "* ]]; then
  echo
  echo "Claude Code CLI: '/codebase-audit', '/codebase-audit:recon', :deploy, :audit,"
  echo "  :fpcheck, :verify <ids>, :report"
  echo "  (Claude also auto-loads the skill from ~/.claude/skills/${SKILL_NAME}/ based"
  echo "   on description triggers, e.g. 'audit this app'.)"
fi
if [[ " ${TARGETS[*]} " == *" codex "* ]]; then
  echo
  echo "Codex CLI: restart Codex (or run '/skills'), then invoke with '\$${SKILL_NAME}'."
  echo "  For a specific phase, pass it as an argument: '\$${SKILL_NAME} recon' (or deploy /"
  echo "  audit / fpcheck / verify <ids> / report). Codex also auto-loads the skill from"
  echo "  either of these dirs, based on description triggers:"
  for d in "${CODEX_SKILL_DIRS[@]}"; do
    echo "    ${d}/"
  done
fi
