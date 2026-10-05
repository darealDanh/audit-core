#requires -Version 5.1
<#
install.ps1 — Install the codebase-audit skill for GitHub Copilot Chat,
Claude Code CLI, and/or OpenAI Codex CLI on Windows (PowerShell). Native
equivalent of install.sh.

Design: each client gets its OWN self-contained copy of the skill.
  - Copilot install root: $HOME\.copilot\skills\codebase-audit\
  - Claude install root:  $HOME\.claude\skills\codebase-audit\
      launchers:          $HOME\.claude\commands\codebase-audit.md
                          $HOME\.claude\commands\codebase-audit\*.md
  - Codex install root:   $HOME\.agents\skills\codebase-audit\

Copilot and Codex auto-discover the skill from their skills dir — no launcher
files. The skill content (SKILL.md, workflows\, references\) and the Claude
launchers all contain the literal string __SKILL_DIR__; this script substitutes
it with the client's own skill dir (in forward-slash form, which Claude Code
accepts on Windows) so every `python3 __SKILL_DIR__/audit.py ...` command in the
installed skill resolves to that client's own copy.
Installing one client does not touch the others.

Usage:
  .\install.ps1                 # install for all clients
  .\install.ps1 copilot         # only Copilot Chat
  .\install.ps1 claude          # only Claude Code CLI
  .\install.ps1 codex           # only Codex CLI
  .\install.ps1 -Insiders       # use VS Code Insiders paths
  .\install.ps1 -Uninstall      # remove the selected clients' launchers
                                #   AND their skill install dirs

(If PowerShell blocks the script, run it for this session only with:
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
 install.sh also works on Windows under Git Bash / WSL.)
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$Targets,
    [switch]$Insiders,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$ScriptDir = $PSScriptRoot
$SkillName = 'codebase-audit'

# ---- resolve targets ----
$valid = @('copilot', 'claude', 'codex', 'all')
if (-not $Targets -or $Targets.Count -eq 0) { $Targets = @('all') }
foreach ($t in $Targets) {
    if ($valid -notcontains $t) { Write-Error "Unknown arg: $t (use copilot | claude | codex | all)"; exit 1 }
}
if ($Targets -contains 'all') { $Targets = @('copilot', 'claude', 'codex') }
$Targets = @($Targets | Select-Object -Unique)

# ---- per-client paths ----
$CopilotSkillDir   = Join-Path $HOME ".copilot\skills\$SkillName"
$ClaudeSkillDir    = Join-Path $HOME ".claude\skills\$SkillName"
$ClaudeCommandsDir = Join-Path $HOME ".claude\commands"
# Codex discovers user-authored skills from ~/.agents/skills, but a sibling
# skill installs to $CODEX_HOME/skills instead; install to both since it is
# not knowable from here which one a given Codex build reads.
$CodexHome = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $HOME '.codex' }
$CodexSkillDirs = @(
    (Join-Path $HOME ".agents\skills\$SkillName"),
    (Join-Path $CodexHome "skills\$SkillName")
)

function Get-CopilotPromptsDir {
    $codeDir = if ($Insiders) { 'Code - Insiders' } else { 'Code' }
    $appData = if ($env:APPDATA) { $env:APPDATA } else { Join-Path $HOME 'AppData\Roaming' }
    return (Join-Path $appData "$codeDir\User\prompts")
}
$CopilotPromptsDir = Get-CopilotPromptsDir

# ---- sanity ----
if (-not (Test-Path (Join-Path $ScriptDir 'SKILL.md'))) {
    Write-Error "SKILL.md not found next to install.ps1."; exit 1
}

# ---- helpers ----

# Copy SKILL.md + workflows\ + references\ from $ScriptDir into $Target.
# Refuses outright if the target IS $ScriptDir (e.g. the repo was cloned
# directly into the install location): see the error text below.
function Install-SkillFiles {
    param([string]$Target)
    New-Item -ItemType Directory -Force -Path $Target | Out-Null
    $absTarget = (Resolve-Path $Target).Path
    if ($absTarget -eq $ScriptDir) {
        Write-Error "ERROR: the source directory IS the install directory: $absTarget"
        Write-Error "       The skill content cannot be substituted in place. Substituting"
        Write-Error "       __SKILL_DIR__ here would rewrite the files of this git checkout,"
        Write-Error "       and skipping the substitution leaves the __SKILL_DIR__ sentinel"
        Write-Error "       in the installed skill, so every 'python3 __SKILL_DIR__/audit.py'"
        Write-Error "       command would fail. A tree cannot be both a source checkout and"
        Write-Error "       an install target."
        Write-Error "       Install from a separate checkout into a different directory, e.g."
        Write-Error "       clone to $HOME\src\codebase-audit and run install.ps1 from there."
        exit 1
    }
    Write-Host "  Copying skill content -> $Target"
    # SKILL.md, workflows\ and references\ all carry `python3 __SKILL_DIR__/audit.py`
    # commands, so they go through the same substitution as the Claude launchers.
    # A plain copy here ships the sentinel literally and every audit.py command in
    # the installed skill fails with "can't open file '...\__SKILL_DIR__\audit.py'".
    Copy-Template (Join-Path $ScriptDir 'SKILL.md') (Join-Path $Target 'SKILL.md') $absTarget -Quiet
    Copy-Item -Force (Join-Path $ScriptDir 'audit.py') (Join-Path $Target 'audit.py')
    foreach ($sub in @('workflows', 'references')) {
        $srcSub = Join-Path $ScriptDir $sub
        if (-not (Test-Path $srcSub)) { continue }
        $dstSub = Join-Path $Target $sub
        # Remove-then-copy, as audit_core already does. `Copy-Item -Recurse` of a
        # directory into an existing same-named directory NESTS it rather than
        # merging, which would bury references\briefs\ one level too deep - and
        # briefs.TEMPLATE_DIR resolves there, so every `audit.py brief` would fail.
        if (Test-Path $dstSub) { Remove-Item -Recurse -Force $dstSub }
        New-Item -ItemType Directory -Force -Path $dstSub | Out-Null
        # Recursive, so references\briefs\ is covered too.
        foreach ($f in Get-ChildItem -Path $srcSub -Recurse -File) {
            $rel = $f.FullName.Substring($srcSub.Length) -replace '^[\\/]+', ''
            $dst = Join-Path $dstSub $rel
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dst) | Out-Null
            if ($f.Extension -in @('.md', '.txt')) {
                Copy-Template $f.FullName $dst $absTarget -Quiet
            } else {
                Copy-Item -Force $f.FullName $dst
            }
        }
    }
    $coreSrc = Join-Path $ScriptDir 'audit_core'
    $coreDst = Join-Path $Target 'audit_core'
    if (Test-Path $coreDst) { Remove-Item -Recurse -Force $coreDst }
    New-Item -ItemType Directory -Path $coreDst | Out-Null
    Copy-Item -Recurse -Force (Join-Path $coreSrc '*') $coreDst
    Get-ChildItem -Path $coreDst -Recurse -Directory -Filter '__pycache__' |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

    $pyver = & python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>$null
    if (-not $pyver) { $pyver = 'none' }
    & python3 (Join-Path $Target 'audit.py') selftest | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Error "audit.py selftest failed in $Target - the install is incomplete."
        Write-Error "       python3 on PATH is $pyver; this skill requires 3.10 or newer."
        Write-Error "       Install a newer python3, or put one earlier on PATH, then re-run."
        exit 1
    }
}

# Substitute __SKILL_DIR__ in $Src with $SkillDir (forward-slash form), write to $Dst.
# UTF-8 without BOM so the launcher's YAML frontmatter is not corrupted.
# `Get-Content -Raw` keeps the file's bytes verbatim, so a CRLF file stays CRLF.
function Copy-Template {
    param([string]$Src, [string]$Dst, [string]$SkillDir, [switch]$Quiet)
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Dst) | Out-Null
    $skillDirFwd = $SkillDir -replace '\\', '/'
    $content = (Get-Content -Raw -LiteralPath $Src) -replace '__SKILL_DIR__', $skillDirFwd
    [System.IO.File]::WriteAllText($Dst, $content, (New-Object System.Text.UTF8Encoding($false)))
    if (-not $Quiet) { Write-Host "  -> $Dst" }
}

function Install-Copilot {
    Write-Host "[copilot]"
    Write-Host "  skill dir:     $CopilotSkillDir"
    Install-SkillFiles $CopilotSkillDir
    # Remove any legacy launcher left by older installs so it can't produce a
    # duplicate /codebase-audit autocomplete entry.
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $CopilotPromptsDir "$SkillName.prompt.md")
}

function Install-Claude {
    Write-Host "[claude]"
    Write-Host "  skill dir:     $ClaudeSkillDir"
    Write-Host "  commands dir:  $ClaudeCommandsDir"
    Install-SkillFiles $ClaudeSkillDir
    # Top-level command
    $topCmd = Join-Path $ScriptDir "claude\commands\$SkillName.md"
    if (Test-Path $topCmd) {
        Copy-Template $topCmd (Join-Path $ClaudeCommandsDir "$SkillName.md") $ClaudeSkillDir
    }
    # Namespaced sub-commands
    $subDir = Join-Path $ScriptDir "claude\commands\$SkillName"
    if (Test-Path $subDir) {
        foreach ($f in Get-ChildItem -File -Filter '*.md' -Path $subDir) {
            Copy-Template $f.FullName (Join-Path $ClaudeCommandsDir "$SkillName\$($f.Name)") $ClaudeSkillDir
        }
    }
}

function Install-Codex {
    Write-Host "[codex]"
    # Codex auto-discovers the skill by its SKILL.md description — no launcher.
    foreach ($d in $CodexSkillDirs) {
        Write-Host "  skill dir:     $d"
        Install-SkillFiles $d
    }
}

function Uninstall-SkillDir {
    param([string]$Target)
    if (Test-Path $Target) {
        $absTarget = (Resolve-Path $Target).Path
        if ($absTarget -ne $ScriptDir) {
            Write-Host "  removing $Target"
            Remove-Item -Recurse -Force $Target
            return
        }
    }
    Write-Host "  (skipping $Target — does not exist OR is the source dir)"
}

function Uninstall-Copilot {
    Write-Host "[copilot] uninstalling"
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $CopilotPromptsDir "$SkillName.prompt.md")
    Uninstall-SkillDir $CopilotSkillDir
}

function Uninstall-Claude {
    Write-Host "[claude] uninstalling"
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $ClaudeCommandsDir "$SkillName.md")
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue (Join-Path $ClaudeCommandsDir $SkillName)
    Uninstall-SkillDir $ClaudeSkillDir
}

function Uninstall-Codex {
    Write-Host "[codex] uninstalling"
    foreach ($d in $CodexSkillDirs) {
        Uninstall-SkillDir $d
    }
}

# ---- run ----
Write-Host "Targets: $($Targets -join ' ')"
Write-Host ""

if ($Uninstall) {
    foreach ($t in $Targets) {
        switch ($t) {
            'copilot' { Uninstall-Copilot }
            'claude'  { Uninstall-Claude }
            'codex'   { Uninstall-Codex }
        }
    }
    Write-Host ""
    Write-Host "Uninstalled."
    exit 0
}

foreach ($t in $Targets) {
    switch ($t) {
        'copilot' { Install-Copilot }
        'claude'  { Install-Claude }
        'codex'   { Install-Codex }
    }
}

Write-Host ""
Write-Host "Done."
if ($Targets -contains 'copilot') {
    Write-Host ""
    Write-Host "Copilot Chat (VS Code): reload window, then type '/codebase-audit'."
    Write-Host "  For a specific phase: '/codebase-audit recon' (or deploy / audit /"
    Write-Host "  fpcheck / verify <ids> / report)."
}
if ($Targets -contains 'claude') {
    Write-Host ""
    Write-Host "Claude Code CLI: '/codebase-audit', '/codebase-audit:recon', :deploy, :audit,"
    Write-Host "  :fpcheck, :verify <ids>, :report"
    Write-Host "  (Claude also auto-loads the skill from ~/.claude/skills/$SkillName/ based"
    Write-Host "   on description triggers, e.g. 'audit this app'.)"
}
if ($Targets -contains 'codex') {
    Write-Host ""
    Write-Host "Codex CLI: restart Codex (or run '/skills'), then invoke with '`$$SkillName'."
    Write-Host "  For a specific phase, pass it as an argument: '`$$SkillName recon' (or deploy /"
    Write-Host "  audit / fpcheck / verify <ids> / report). Codex also auto-loads the skill from"
    Write-Host "  either of these dirs, based on description triggers:"
    foreach ($d in $CodexSkillDirs) {
        Write-Host "    $d"
    }
}
