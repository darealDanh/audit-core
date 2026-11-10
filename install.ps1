#requires -Version 5.1
<#
install.ps1 — Install the codebase-audit and/or firmware-audit skills for GitHub
Copilot Chat, Claude Code CLI, and/or OpenAI Codex CLI on Windows (PowerShell).
Native equivalent of install.sh.

Design: each (skill, client) pair gets its OWN self-contained copy. For a skill
<s>:
  - Copilot install root: $HOME\.copilot\skills\<s>\
  - Claude install root:  $HOME\.claude\skills\<s>\
      launchers:          $HOME\.claude\commands\<s>.md
                          $HOME\.claude\commands\<s>\*.md
  - Codex install roots:  $HOME\.agents\skills\<s>\ and
                          ${CODEX_HOME:-$HOME\.codex}\skills\<s>\

The operator-facing surface (SKILL.md, references\, workflows\ if any, and the
Claude launchers) comes from the skill's surface dir — the repo root for
codebase-audit, <root>\firmware-audit\ for firmware-audit. The shared audit.py +
audit_core\ always come from the repo root (the core dir), so both skills vendor
an identical core. The surface files carry the literal string __SKILL_DIR__; this
script substitutes it with that install's own skill dir (in forward-slash form,
which Claude Code accepts on Windows) so every `python3 __SKILL_DIR__/audit.py`
command resolves to that skill's own copy. audit.py / audit_core are copied
verbatim (never substituted). Installing one (skill, client) pair does not touch
the others.

Usage:
  .\install.ps1                            # all skills, all clients
  .\install.ps1 copilot                    # only Copilot Chat
  .\install.ps1 claude                     # only Claude Code CLI
  .\install.ps1 codex                      # only Codex CLI
  .\install.ps1 -Skill firmware-audit      # only the firmware-audit skill
  .\install.ps1 -Skill codebase-audit      # only the codebase-audit skill
  .\install.ps1 -Skill all                 # both skills (default)
  .\install.ps1 -Insiders                  # use VS Code Insiders paths
  .\install.ps1 -Uninstall                 # remove the selected skills' launchers
                                           #   AND their skill install dirs

(If PowerShell blocks the script, run it for this session only with:
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
 install.sh also works on Windows under Git Bash / WSL.)
#>
# PositionalBinding=$false: only params with an explicit Position are positional,
# so bare client args bind to $Targets (Position 0) and -Skill stays named-only —
# it is never swallowed into the ValueFromRemainingArguments $Targets list.
[CmdletBinding(PositionalBinding = $false)]
param(
    # A real named param, declared BEFORE the remaining-args catch-all so
    # `-Skill firmware-audit` binds here instead of being swallowed into $Targets.
    [string]$Skill = 'all',
    [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
    [string[]]$Targets,
    [switch]$Insiders,
    [switch]$Uninstall
)

$ErrorActionPreference = 'Stop'
$ScriptDir = $PSScriptRoot
# $ScriptDir is the repo-root checkout: the core dir (audit.py + audit_core\) and
# the codebase-audit surface dir.
$CoreDir = $ScriptDir

# ---- resolve targets (clients) ----
$valid = @('copilot', 'claude', 'codex', 'all')
if (-not $Targets -or $Targets.Count -eq 0) { $Targets = @('all') }
foreach ($t in $Targets) {
    if ($valid -notcontains $t) { Write-Error "Unknown arg: $t (use copilot | claude | codex | all)"; exit 1 }
}
if ($Targets -contains 'all') { $Targets = @('copilot', 'claude', 'codex') }
$Targets = @($Targets | Select-Object -Unique)

# ---- resolve skills ----
$validSkills = @('codebase-audit', 'firmware-audit', 'all')
if (-not $Skill) { $Skill = 'all' }
if ($validSkills -notcontains $Skill) {
    Write-Error "Unknown skill: $Skill (use codebase-audit | firmware-audit | all)"; exit 1
}
$Skills = if ($Skill -eq 'all') { @('codebase-audit', 'firmware-audit') } else { @($Skill) }

# ---- per-client paths (the command dir is skill-independent) ----
$ClaudeCommandsDir = Join-Path $HOME ".claude\commands"
$CodexHome = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $HOME '.codex' }

function Get-CopilotPromptsDir {
    $codeDir = if ($Insiders) { 'Code - Insiders' } else { 'Code' }
    $appData = if ($env:APPDATA) { $env:APPDATA } else { Join-Path $HOME 'AppData\Roaming' }
    return (Join-Path $appData "$codeDir\User\prompts")
}
$CopilotPromptsDir = Get-CopilotPromptsDir

# ---- sanity ----
if (-not (Test-Path (Join-Path $CoreDir 'SKILL.md'))) {
    Write-Error "SKILL.md not found next to install.ps1."; exit 1
}

# Resolve the surface dir (SKILL.md, references\, workflows\, launchers) for a
# skill. codebase-audit's surface IS the repo root; firmware-audit's surface is
# the firmware-audit\ subtree. The core (audit.py + audit_core\) is always
# $CoreDir regardless.
function Get-SurfaceDir {
    param([string]$SkillName)
    if ($SkillName -eq 'firmware-audit') { return (Join-Path $CoreDir 'firmware-audit') }
    return $CoreDir
}

# ---- helpers ----

# Copy the surface (SKILL.md + workflows\ + references\) from -SurfaceDir and the
# shared audit.py + audit_core\ from -CoreDir into -Dest, substituting
# __SKILL_DIR__ in the surface as it goes. Refuses outright if -Dest IS the
# repo-root checkout (-CoreDir): see the error text below.
function Install-SkillFiles {
    param([string]$SurfaceDir, [string]$CoreDir, [string]$Dest)
    New-Item -ItemType Directory -Force -Path $Dest | Out-Null
    $absTarget = (Resolve-Path $Dest).Path
    if ($absTarget -eq $CoreDir) {
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
    Write-Host "  Copying skill content -> $Dest"
    # SKILL.md, workflows\ and references\ all carry `python3 __SKILL_DIR__/audit.py`
    # commands, so they go through the same substitution as the Claude launchers.
    # A plain copy here ships the sentinel literally and every audit.py command in
    # the installed skill fails with "can't open file '...\__SKILL_DIR__\audit.py'".
    Copy-Template (Join-Path $SurfaceDir 'SKILL.md') (Join-Path $Dest 'SKILL.md') $absTarget -Quiet
    # audit.py + audit_core\ come from the core dir (repo root) and are copied
    # verbatim — they must NOT be substituted.
    Copy-Item -Force (Join-Path $CoreDir 'audit.py') (Join-Path $Dest 'audit.py')
    foreach ($sub in @('workflows', 'references')) {
        $srcSub = Join-Path $SurfaceDir $sub
        # firmware-audit ships no workflows\; skip gracefully when absent.
        if (-not (Test-Path $srcSub)) { continue }
        $dstSub = Join-Path $Dest $sub
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
    $coreSrc = Join-Path $CoreDir 'audit_core'
    $coreDst = Join-Path $Dest 'audit_core'
    if (Test-Path $coreDst) { Remove-Item -Recurse -Force $coreDst }
    New-Item -ItemType Directory -Path $coreDst | Out-Null
    Copy-Item -Recurse -Force (Join-Path $coreSrc '*') $coreDst
    Get-ChildItem -Path $coreDst -Recurse -Directory -Filter '__pycache__' |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

    $pyver = & python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>$null
    if (-not $pyver) { $pyver = 'none' }
    & python3 (Join-Path $Dest 'audit.py') selftest | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Error "audit.py selftest failed in $Dest - the install is incomplete."
        Write-Error "       python3 on PATH is $pyver; this skill requires 3.10 or newer."
        Write-Error "       Install a newer python3, or put one earlier on PATH, then re-run."
        exit 1
    }
    Write-Host "  selftest OK"
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
    param([string]$SkillName, [string]$SurfaceDir, [string]$CopilotSkillDir)
    Write-Host "[copilot] $SkillName"
    Write-Host "  skill dir:     $CopilotSkillDir"
    Install-SkillFiles $SurfaceDir $CoreDir $CopilotSkillDir
    # Remove any legacy launcher left by older installs so it can't produce a
    # duplicate /$SkillName autocomplete entry.
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $CopilotPromptsDir "$SkillName.prompt.md")
}

function Install-Claude {
    param([string]$SkillName, [string]$SurfaceDir, [string]$ClaudeSkillDir)
    Write-Host "[claude] $SkillName"
    Write-Host "  skill dir:     $ClaudeSkillDir"
    Write-Host "  commands dir:  $ClaudeCommandsDir"
    Install-SkillFiles $SurfaceDir $CoreDir $ClaudeSkillDir
    # Top-level command
    $topCmd = Join-Path $SurfaceDir "claude\commands\$SkillName.md"
    if (Test-Path $topCmd) {
        Copy-Template $topCmd (Join-Path $ClaudeCommandsDir "$SkillName.md") $ClaudeSkillDir
    }
    # Namespaced sub-commands
    $subDir = Join-Path $SurfaceDir "claude\commands\$SkillName"
    if (Test-Path $subDir) {
        foreach ($f in Get-ChildItem -File -Filter '*.md' -Path $subDir) {
            Copy-Template $f.FullName (Join-Path $ClaudeCommandsDir "$SkillName\$($f.Name)") $ClaudeSkillDir
        }
    }
}

function Install-Codex {
    param([string]$SkillName, [string]$SurfaceDir, [string[]]$CodexSkillDirs)
    Write-Host "[codex] $SkillName"
    # Codex auto-discovers the skill by its SKILL.md description — no launcher.
    foreach ($d in $CodexSkillDirs) {
        Write-Host "  skill dir:     $d"
        Install-SkillFiles $SurfaceDir $CoreDir $d
    }
}

function Uninstall-SkillDir {
    param([string]$Target)
    if (Test-Path $Target) {
        $absTarget = (Resolve-Path $Target).Path
        if ($absTarget -ne $CoreDir) {
            Write-Host "  removing $Target"
            Remove-Item -Recurse -Force $Target
            return
        }
    }
    Write-Host "  (skipping $Target — does not exist OR is the source dir)"
}

function Uninstall-Copilot {
    param([string]$SkillName, [string]$CopilotSkillDir)
    Write-Host "[copilot] $SkillName uninstalling"
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $CopilotPromptsDir "$SkillName.prompt.md")
    Uninstall-SkillDir $CopilotSkillDir
}

function Uninstall-Claude {
    param([string]$SkillName, [string]$ClaudeSkillDir)
    Write-Host "[claude] $SkillName uninstalling"
    Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $ClaudeCommandsDir "$SkillName.md")
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue (Join-Path $ClaudeCommandsDir $SkillName)
    Uninstall-SkillDir $ClaudeSkillDir
}

function Uninstall-Codex {
    param([string]$SkillName, [string[]]$CodexSkillDirs)
    Write-Host "[codex] $SkillName uninstalling"
    foreach ($d in $CodexSkillDirs) {
        Uninstall-SkillDir $d
    }
}

# ---- run ----
Write-Host "Skills:  $($Skills -join ' ')"
Write-Host "Targets: $($Targets -join ' ')"
Write-Host ""

foreach ($s in $Skills) {
    $surfaceDir      = Get-SurfaceDir $s
    $copilotSkillDir = Join-Path $HOME ".copilot\skills\$s"
    $claudeSkillDir  = Join-Path $HOME ".claude\skills\$s"
    $codexSkillDirs  = @(
        (Join-Path $HOME ".agents\skills\$s"),
        (Join-Path $CodexHome "skills\$s")
    )

    if ($Uninstall) {
        foreach ($t in $Targets) {
            switch ($t) {
                'copilot' { Uninstall-Copilot $s $copilotSkillDir }
                'claude'  { Uninstall-Claude $s $claudeSkillDir }
                'codex'   { Uninstall-Codex $s $codexSkillDirs }
            }
        }
        continue
    }

    foreach ($t in $Targets) {
        switch ($t) {
            'copilot' { Install-Copilot $s $surfaceDir $copilotSkillDir }
            'claude'  { Install-Claude $s $surfaceDir $claudeSkillDir }
            'codex'   { Install-Codex $s $surfaceDir $codexSkillDirs }
        }
    }
}

if ($Uninstall) {
    Write-Host ""
    Write-Host "Uninstalled."
    exit 0
}

Write-Host ""
Write-Host "Done."
foreach ($s in $Skills) {
    $phases = if ($s -eq 'firmware-audit') {
        'qualify (or acquire / triage / diff / surface / hunt / fpcheck / chain / dive / decide / firmware-report)'
    } else {
        'recon (or deploy / audit / fpcheck / verify <ids> / report)'
    }
    $firstPhase = ($phases -split ' ')[0]
    $codexSkillDirs = @(
        (Join-Path $HOME ".agents\skills\$s"),
        (Join-Path $CodexHome "skills\$s")
    )
    if ($Targets -contains 'copilot') {
        Write-Host ""
        Write-Host "Copilot Chat (VS Code) [$s]: reload window, then type '/$s'."
        Write-Host "  For a specific phase: '/$s $phases'."
    }
    if ($Targets -contains 'claude') {
        Write-Host ""
        Write-Host "Claude Code CLI [$s]: '/$s', then phase subcommands, e.g. '/${s}:$firstPhase'."
        Write-Host "  (Claude also auto-loads the skill from ~/.claude/skills/$s/ based"
        Write-Host "   on description triggers.)"
    }
    if ($Targets -contains 'codex') {
        Write-Host ""
        Write-Host "Codex CLI [$s]: restart Codex (or run '/skills'), then invoke with '`$$s'."
        Write-Host "  For a specific phase, pass it as an argument: '`$$s $phases'."
        Write-Host "  Codex also auto-loads the skill from either of these dirs:"
        foreach ($d in $codexSkillDirs) {
            Write-Host "    $d"
        }
    }
}
