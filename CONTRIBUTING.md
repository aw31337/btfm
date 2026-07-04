# Contributing to BTFM

Contributions are welcome and appreciated. Here's how to do it cleanly.

## What We Want

- New scripts that fill gaps in the book's coverage
- Fixes to existing scripts (bugs, compatibility, updated syntax)
- Cheatsheet additions — commands, event IDs, tool flags
- Real-world refinements from field use

## What We Don't Want

- Exploits or offensive tooling — this is a blue team repo
- Scripts that require paid tools without a free equivalent
- Content that duplicates the book verbatim (that's what the book is for)

## How to Submit

1. Fork the repo
2. Create a branch: `git checkout -b add/your-script-name`
3. Add your content in the right folder (match the existing structure)
4. Include a comment block at the top of every script:
   ```
   # Script: <name>
   # Purpose: <one line>
   # Usage: <example command>
   # Requirements: <tools needed>
   # BTFM Reference: <section if applicable>
   ```
5. Open a Pull Request with a clear title and description

## Code Standards

- Bash: POSIX-compatible where possible; note if bash 4+ is required
- PowerShell: PS 5.1 minimum; note if PS 7 is required
- Python: 3.8+; no external dependencies unless clearly documented
- No hardcoded IPs, credentials, or environment-specific paths

## Issues

Open an Issue for:
- Broken scripts
- Outdated commands (tools that changed their flags)
- Requests for new content areas

Label your issues clearly: `bug`, `enhancement`, `question`.
