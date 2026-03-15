---
name: bci-threat-model
description: This skill should be used when the user asks to "threat model a BCI", "threat model a brain-computer interface", "security assessment for a BCI device", "BCI risk assessment", "what are the threats to my BCI product", "medical device threat model", or wants to systematically identify security threats for a neurotechnology system. Also use when discussing FDA premarket cybersecurity requirements for neural devices.
version: 1.0.0
---

# BCI Threat Model Generator

Guide the user through a structured threat modeling process for their BCI system, producing a document they can use for security reviews, regulatory submissions, or internal assessments.

## Data Location

- Techniques: `${CLAUDE_PLUGIN_ROOT}/data/tara-techniques.json`
- Security controls: `${CLAUDE_PLUGIN_ROOT}/data/security-controls.json`
- Guardrails: `${CLAUDE_PLUGIN_ROOT}/data/guardrails.json`

## Step 1: Device Profile (ask the user)

Ask these 4 questions:

1. **Device class:** What type of BCI?
   - Consumer EEG (Muse, Emotiv, OpenBCI)
   - Research-grade EEG (g.tec, BrainProducts, ANT Neuro)
   - Implanted/invasive BCI (Neuralink, Blackrock, Synchron)
   - Neurostimulation device (tDCS, tACS, TMS)
   - Neurofeedback system
   - Other (describe)

2. **Signal types:** What neural signals does it read or write?
   - EEG, ECoG, LFP, single-unit, fNIRS, EMG, other

3. **Connectivity:** How does data move?
   - Bluetooth (Classic/BLE), WiFi, USB/Serial, Cloud API, Wired only

4. **Deployment context:**
   - Clinical (hospital/clinic), Consumer (home use), Research (lab), Military/defense

## Step 2: Attack Surface Enumeration

Based on the device profile, identify the relevant QIF bands:
- **Consumer EEG:** I0 (minimal — dry electrodes), S1 (analog frontend), N1-N2 (processing), transport (BLE/WiFi), cloud API
- **Research EEG:** I0 (gel electrodes), S1, network (LSL), file storage (EDF/BDF), analysis pipeline
- **Implanted BCI:** I0 (critical — electrode-tissue), firmware, wireless telemetry, clinical software
- **Neurostimulation:** I0 (critical — active stimulation), firmware, dosage control, session logging

## Step 3: TARA Technique Filtering

Read the TARA techniques from the data file. Filter to the techniques relevant for the device profile:

- **Consumer EEG:** Focus on transport security, data exfiltration, cloud API abuse, sensor spoofing
- **Research EEG:** Focus on LSL security, file storage PII, pipeline integrity, calibration poisoning
- **Implanted BCI:** Focus on I0 techniques (signal injection, impedance manipulation), firmware integrity, wireless telemetry encryption
- **Neurostimulation:** Focus on dosage manipulation, firmware tampering, session integrity

Present the top 10-15 most relevant techniques with NISS scores.

## Step 4: Risk Assessment Matrix

For each applicable technique, produce:

| Technique | NISS | Likelihood | Existing Controls | Residual Risk |
|-----------|------|------------|-------------------|---------------|
| [ID: Name] | [score] | [based on device class] | [what the user has] | [gap] |

Ask the user what controls they already have in place. Adjust residual risk accordingly.

## Step 5: Mitigation Recommendations

For each high-residual-risk technique, provide:
1. Specific defensive control (from security-controls.json)
2. Implementation guidance (concrete, not abstract)
3. Priority (based on NISS score and implementation effort)

## Step 6: Generate Report

Produce a structured threat model document in Markdown:

```markdown
# BCI Threat Model: [Device Name]

**Date:** [today]
**Device class:** [from Step 1]
**Generated with:** BCI Security Tools v1.0 (qinnovate.com)

## Device Profile
[Summary from Step 1]

## Attack Surface
[From Step 2]

## Threat Assessment
[Risk matrix from Step 4]

## Recommended Mitigations
[Priority-ordered from Step 5]

## Methodology
This threat model uses the TARA technique catalog and NISS scoring system
from the QIF framework. TARA and NISS are proposed research tools that have
not been independently validated or adopted by any standards body. This
assessment supplements, and does not replace, risk analysis per IEC 14971,
IEC 62443, and applicable FDA premarket cybersecurity guidance.

## Evidence Basis
Techniques marked CONFIRMED or DEMONSTRATED are supported by published
research. Techniques marked THEORETICAL are extrapolated from known
attack patterns and have not been independently reproduced.
```

## Mandatory Constraints

- This tool generates threat model DRAFTS, not validated risk assessments
- Always include the methodology disclaimer
- Filter techniques by evidence tier: for regulatory contexts, recommend restricting to CONFIRMED + DEMONSTRATED
- Never present theoretical techniques as confirmed threats
- Clinical impact statements require "for threat modeling purposes" qualifier
- The report must be useful without the plugin installed (standalone Markdown)
