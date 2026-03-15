# BCI Security

Threat modeling and security analysis for brain-computer interfaces. The first neurotechnology security tool on any AI coding platform.

**Status:** Research tool. Proposed framework, not an adopted standard. Not independently peer-reviewed.

## What It Does

- **Scans BCI code** for unsafe patterns (unencrypted neural streams, PII in data files, hardcoded credentials)
- **Looks up threat techniques** from a catalog of 135 attacks targeting neural systems
- **Scores severity** using NISS, a neural-specific supplement to CVSS
- **Generates threat models** for BCI devices (consumer EEG, research systems, clinical implants)
- **Checks neuroethics compliance** against 8 published guardrails

## Quick Start

```
/bci-scan --demo
```

That's it. Scans a sample EEG device config and shows you what an attacker could exploit. Takes 30 seconds.

## Commands

| Command | What It Does |
|---------|-------------|
| `/bci-scan --demo` | Scan a sample device — start here |
| `/bci-scan <file>` | Scan your BCI code or config |
| `/bci explain <ID>` | Explain a threat technique in plain English |
| `/bci report` | Generate a shareable threat assessment |
| `/bci learn <topic>` | Interactive walkthrough (tara, niss, neuroethics, quickstart) |
| `/bci glossary [term]` | Quick BCI security definitions |

## The Core Insight

104 out of 135 cataloged attack techniques share mechanisms with therapeutic treatments. tDCS for depression uses the same current delivery as signal injection. Neurofeedback training uses the same reward pathways as cognitive manipulation.

The difference between therapy and attack is consent, dosage, and oversight.

## What's Inside

- **TARA**: 135 threat techniques across 11 biological domains, each with evidence tiers (CONFIRMED / DEMONSTRATED / THEORETICAL)
- **NISS**: 6-dimensional severity scoring — Biological Impact, Coupling Risk, Coherence Disruption, Consent Violation, Reversibility, Neuroplasticity
- **3 Code Scanning Rules**: Transport encryption, data storage PII, API credential handling
- **8 Neuroethics Guardrails**: From Morse, Poldrack, Racine, Ienca, Kellmeyer, Wexler, Tennison, Vul/Eklund
- **3 Sample Configs**: Consumer EEG, research system, clinical implant

## Who This Is For

- **Neurotech startups** building BCI products
- **Medical device security teams** doing threat assessments
- **BCI researchers** who want structured security analysis
- **Students** entering the neurosecurity field

## Important Caveats

This plugin is built on the QIF framework, which is:
- **Proposed** — not adopted by any standards body
- **Unvalidated** — not independently peer-reviewed or replicated
- **In development** — not production-ready for clinical use

NISS supplements CVSS. It does not replace it. TARA supplements MITRE ATT&CK for a domain ATT&CK does not cover. Neither is a standard.

Every clinical impact statement in this plugin includes "for threat modeling purposes" — these are threat modeling categories, not clinical predictions.

## Licenses

- **Code:** Apache 2.0 (`LICENSE-CODE`)
- **Data** (TARA catalog, NISS scores, guardrails): CC BY-SA 4.0 (`LICENSE-DATA`)

## Contributing

See `CONTRIBUTING.md` for the TARA Technique Proposal process.

## Built By

[QInnovate](https://qinnovate.com) — Open neurosecurity research.
