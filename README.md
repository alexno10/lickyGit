# 🔍 lickyGit

> **Lick every secret out of your Git history.**

A modern, high-performance, cross-platform Git secret scanner that detects leaked credentials, API keys, tokens, and sensitive data across your commit history, staging area, and pull requests.

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔑 **35+ Built-in Rules** | AWS, GitHub, GitLab, Slack, Stripe, Google, Azure, npm, PyPI, Docker, and more (pre-compiled with regex boundary guards) |
| 📊 **Shannon Entropy** | Detect high-entropy strings (random API keys, tokens) even without pattern rules |
| 🔤 **Keyword Detection** | Find `password = "..."`, `api_key: "..."` assignments with intelligent false-positive heuristics |
| ⚡ **Blob SHA Caching** | Multi-commit history scans avoid redundant Git object re-scanning |
| 🪝 **Staged Changes Scanning** | Scan staged index changes (`--staged`) for zero-leak pre-commit protection |
| ⏩ **Incremental & PR Scanning** | Scan only commits since a commit (`--since-commit`) or between branches (`--diff`) |
| 🚨 **Smart CI Failure** | Exit with failure only if secrets meet or exceed a severity threshold (`--fail-on-severity`) |
| 📑 **Baseline Support** | Suppress existing legacy findings with `--baseline` and `--generate-baseline` |
| 🖥️ **Cross-Platform** | Works seamlessly on Windows, macOS, and Linux (normalizes path separators and handles Git pack locks) |
| 📝 **6 Output Formats** | Terminal (Rich), JSON, CSV, SARIF 2.1.0, GitLab Code Quality, and interactive dark-mode HTML |
| 🚫 **Allowlisting** | Suppress known false positives with `.lickygit-allow` (supports regex and path scoping) |
| ⚙️ **Config Validation** | Project-level `.lickygit.toml` with `config check` and `config show` utilities |
| 🧩 **Custom Rules** | Define your own regex rules in TOML or YAML |
| 🐙 **Official GitHub Action** | Plug-and-play CI integration with code scanning SARIF upload and script injection hardening |

---

## 📦 Installation

```bash
pip install lickygit
```

Or install from source:

```bash
git clone https://github.com/alexno10/lickyGit.git
cd lickyGit
pip install -e .
```

---

## 🚀 Quick Start

```bash
# Scan entire repository history
lickygit scan

# Scan only currently staged changes (pre-commit)
lickygit scan --staged

# Scan only the HEAD commit
lickygit scan --head-only

# Incremental scan (only new commits since a specific commit)
lickygit scan --since-commit abc1234

# Pull Request diff-aware scan (only commits between main and HEAD)
lickygit scan --diff main

# Only report HIGH and CRITICAL findings
lickygit scan --severity high

# Only exit with error code 1 if CRITICAL findings exist (warn on lower)
lickygit scan --fail-on-severity critical

# Scan a remote repository and clean up afterwards
lickygit scan --url https://github.com/user/repo.git --delete

# Generate an interactive HTML report
lickygit scan -f html -o report.html

# Output SARIF 2.1.0 (for GitHub Code Scanning & IDEs)
lickygit scan -f sarif -o results.sarif

# Output GitLab Code Quality JSON (for GitLab MR widgets)
lickygit scan -f gitlab -o gl-code-quality-report.json
```

---

## 🪝 Pre-commit Hook

Block accidental secret commits right on your machine.

### Built-in Hook

```bash
# Install the pre-commit hook (automatically scans staged changes)
lickygit hook install

# Block commits only when secrets are >= HIGH severity
lickygit hook install --severity high

# Uninstall
lickygit hook uninstall
```

### With Pre-commit Framework

Add this to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/alexno10/lickyGit
    rev: v1.1.0
    hooks:
      - id: lickygit
```

---

## 📑 Baseline Management (CI/CD)

Prevent CI pipelines from failing on existing legacy secrets while blocking any **new** leaks in pull requests:

```bash
# 1. Generate a baseline file of existing findings
lickygit scan --generate-baseline .lickygit-baseline.json

# 2. Run future scans against the baseline (ignores known baseline findings)
lickygit scan --baseline .lickygit-baseline.json
```

---

## 🐙 GitHub Action

Add automated secret scanning to your GitHub repository:

```yaml
name: Security Audit

on: [push, pull_request]

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write

    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Scan with lickyGit
        uses: alexno10/lickyGit@v1.1.0
        with:
          severity: 'high'
          upload-sarif: 'true'
```

---

## 🦊 GitLab CI/CD

Integrate directly with GitLab Merge Request Code Quality widget:

```yaml
lickygit_scan:
  image: python:3.11-slim
  stage: test
  before_script:
    - apt-get update && apt-get install -y git
    - pip install lickygit
  script:
    - lickygit scan -f gitlab -o gl-code-quality-report.json --fail-on-severity high
  artifacts:
    reports:
      codequality: gl-code-quality-report.json
```

---

## ⚙️ Configuration & Diagnostics

Create `.lickygit.toml` in your project root:

```toml
[scan]
head_only = false
max_workers = 4
severity = "medium"           # low | medium | high | critical
fail_on_severity = "high"     # exit code 1 only if findings >= high
max_file_size = 5242880       # 5MB limit

[detection]
use_entropy = true
use_keywords = true
use_builtin_rules = true
entropy_threshold = 4.5

[filters]
exclude = ["*.lock", "vendor/*", "*.min.js", "go.sum", "*.schema.json"]
allowlist = ".lickygit-allow"
baseline = ".lickygit-baseline.json"

[output]
format = "terminal"
verbose = false
```

### Configuration CLI Tools

```bash
# Check your .lickygit.toml for unknown keys, typos, or deprecated syntax
lickygit config check

# Print the active, merged configuration values
lickygit config show
```

---

## 🚫 Allowlisting

Create `.lickygit-allow` to suppress specific known false positives:

```
# Exact substring match
EXAMPLE_TOKEN_TO_ALLOW

# Regex match
regex:test_token_[a-z]+

# Scoped to specific files (supports glob matching)
scope:*.test.py my_test_secret

# With reason annotation
EXAMPLE_TOKEN_TO_ALLOW # Safe development mock token
```

---

## 🧩 Custom Rules

Define project-specific secret patterns in TOML or YAML:

```toml
[[rules]]
id = "internal-service-token"
name = "Internal Service Token"
pattern = "INT_SVC_[A-Z0-9]{32}"
severity = "HIGH"
description = "Internal service authentication token"
```

```bash
lickygit scan --custom-rules my-rules.toml
```

---

## 📊 Output Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Terminal | `-f terminal` | Interactive, color-coded summary table (default) |
| HTML | `-f html` | Standalone interactive dark-mode dashboard |
| SARIF | `-f sarif` | GitHub Code Scanning / Security Tab (O(1) index, RFC URI compliant) |
| GitLab | `-f gitlab` | GitLab CI Code Quality Report JSON |
| JSON | `-f json` | CI/CD pipelines and automation scripts |
| CSV | `-f csv` | Spreadsheet audits and compliance reports |

---

## 🏗️ Architecture

```
lickygit/
├── core/           # Scanner, GitWalker (index/staged, commit history, diff ranges), Finding model
├── detection/      # Entropy analyzer, Regex pattern matcher, Keywords detector, Rules
├── filters/        # Allowlist, Path filter, Value filter, Baseline manager
└── output/         # Terminal (Rich), JSON, CSV, SARIF 2.1.0, GitLab Code Quality, HTML Report
```

---

## 📄 License

MIT
