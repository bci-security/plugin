---
description: BCI security toolkit — threat modeling, code scanning, and neuroethics compliance for brain-computer interfaces
argument-hint: [scan|explain|report|learn|glossary] [args]
allowed-tools: [Read, Glob, Grep]
---

# BCI Security Tools

You are the entry point for the BCI Security plugin. Route the user to the right capability based on their request.

## Arguments

The user invoked: `/bci $ARGUMENTS`

## Routing

Based on the arguments:

- **No arguments or "help"**: Show a brief welcome and available commands
- **"scan"**: Tell the user to run `/bci-scan` (with `--demo` for first-timers)
- **"explain <ID>"**: Look up the technique ID in the TARA data and explain it in plain English
- **"report"**: Generate a shareable threat assessment from the most recent scan
- **"learn <topic>"**: Start an interactive walkthrough on tara, niss, or neuroethics
- **"glossary [term]"**: Look up a BCI security term

## Welcome Message (when no arguments)

Show this:

```
BCI Security Tools v1.0

Commands:
  /bci-scan --demo          Scan a sample BCI device config (start here)
  /bci-scan <file>          Scan your own BCI code or config
  /bci explain <ID>         Explain a TARA technique in plain English
  /bci report               Generate a shareable threat assessment
  /bci learn <topic>        Interactive walkthrough (topics: tara, niss, neuroethics)
  /bci glossary [term]      Quick definitions

First time? Run /bci-scan --demo to see a threat report in 30 seconds.
```

## For /bci explain <ID>

Read the TARA techniques data from `${CLAUDE_PLUGIN_ROOT}/data/tara-techniques.json`. Find the technique matching the ID (e.g., "QIF-T0001" or just "T0001"). Present it in three layers:

**Layer 1 (always show):**
- Technique name and one-sentence summary
- NISS score with severity
- Status (CONFIRMED/DEMONSTRATED/THEORETICAL)

**Layer 2 (show by default):**
- What it does in plain English (2-3 sentences, no jargon)
- Why it matters
- The therapeutic analog (if dual_use is confirmed)
- Affected QIF bands

**Layer 3 (mention available):**
- Tell the user they can ask for the full technique card with sources, engineering parameters, and defensive controls.

Always include the neuromodesty qualifier: "for threat modeling purposes" when describing clinical impacts.

## For /bci glossary

Key terms to define:
- **BCI**: Brain-Computer Interface — a device that reads or writes neural signals
- **TARA**: Threat catalog of 135 attack techniques targeting BCI systems
- **NISS**: Neural Impact Scoring System — severity scoring for BCI threats (like CVSS but for neural systems)
- **QIF**: The framework that organizes BCI security analysis
- **LSL**: Lab Streaming Layer — a protocol for streaming neural data (no built-in encryption)
- **EDF/BDF**: European Data Format — common file format for storing neural recordings
- **Neuromodesty**: The principle that neural correlates do not prove causation (Morse 2006)
- **Dual-use**: When the same mechanism can be used for therapy or attack — the difference is consent, dosage, and oversight

Note: QIF, TARA, and NISS are proposed research tools, not adopted standards. They have not been independently peer-reviewed.
