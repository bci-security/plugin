# BCI Device Integration Guide

This guide covers how the BCI Security plugin integrates with common BCI hardware and software platforms. These are community-supported integrations based on open-source SDKs and published APIs. **QInnovate is not affiliated with any device manufacturer.**

## Important Security Notice

Before connecting any BCI device to an AI-assisted analysis pipeline:

1. **Your network must be secure.** BCI data streams (especially LSL and BLE) are often unencrypted. Ensure your lab or clinical network is segmented, monitored, and access-controlled. Consult your organization's security team.

2. **Compliance review is required.** If your BCI data involves human subjects, patients, or identifiable individuals, your organization should have completed a security review and data governance assessment before processing with any AI platform. If you are using an AI coding platform, your institution has likely already performed the necessary compliance checks for that platform's data processing agreement.

3. **This plugin does not connect to devices.** It scans code that connects to devices. The plugin reads your source files and configuration — it never accesses hardware, streams, or raw neural data directly.

4. **Have security experts review your integration.** This plugin flags issues. Qualified security engineers, compliance officers, and (for clinical use) biomedical engineers should review findings and validate remediations.

## Supported Platforms

### OpenBCI (Cyton, Ganglion, Daisy)

**SDK:** OpenBCI Python SDK, BrainFlow
**Connection:** USB-serial (Cyton via dongle), BLE (Ganglion)
**What the scanner detects:**

```python
# Rule 1 catches:
from OpenBCI import OpenBCICyton
board = OpenBCICyton(port='/dev/ttyUSB0')  # Serial — no device auth

# Rule 1 catches via BrainFlow:
from brainflow.board_shim import BoardShim, BrainFlowInputParams
params = BrainFlowInputParams()
board = BoardShim(BoardIds.CYTON_BOARD.value, params)

# Rule 7 catches (BrainFlow export):
DataFilter.write_file(data, 'recording.csv', 'w')  # Check filename PII
```

**Security considerations:**
- Cyton's RFDuino 2.4 GHz radio has no encryption. Anyone within radio range can receive the stream.
- Ganglion uses BLE without bonding by default. Enable LE Secure Connections.
- LSL streams from OpenBCI are unencrypted. Wrap in TLS via stunnel or use BrainFlow's encrypted WebSocket mode.
- Run `/bci anonymize .` before sharing any recorded data.

### BrainFlow (Multi-Device SDK)

**SDK:** BrainFlow Python/C++/Java/C#
**Devices:** 20+ boards including OpenBCI, Muse, Neurosity, g.tec, BrainBit, Notion
**What the scanner detects:**

```python
# Rule 1: Transport security
board = BoardShim(board_id, params)
# Checks ip_protocol for encryption. Flags if unencrypted.

# Rule 7: Extended board detection
BoardShim(BoardIds.GANGLION_BOARD.value, params)  # BLE-SPP, flag
BoardShim(BoardIds.MUSE_S_BOARD.value, params)    # BLE, flag
BoardShim(BoardIds.MUSE_2_BOARD.value, params)    # BLE, flag

# Rule 7: File export PII check
DataFilter.write_file(data, filename, 'w')
```

**Security considerations:**
- BrainFlow supports encrypted WebSocket transport (`ip_protocol=2`). Use it.
- Different boards have different security profiles. The scanner maps findings to the specific board ID.
- BrainFlow's streaming layer is a transport wrapper — encryption depends on the underlying protocol.

### MNE-Python (Research Analysis)

**SDK:** MNE-Python
**Formats:** FIF, EDF, BDF, XDF, NWB, EEGLAB .set
**What the scanner detects:**

```python
# Rule 7: Read without anonymization
raw = mne.io.read_raw_edf('recording.edf')
raw.save('output.fif')  # No anonymize() call — flagged

# Rule 7: Anonymization present (no flag)
raw = mne.io.read_raw_edf('recording.edf')
raw.anonymize()
raw.save('output.fif')  # Clean

# Rule 7: ML training pipeline
from mne.decoding import CSP
csp = CSP()
csp.fit(epochs_data, labels)  # Training data source checked

# Rule 2: PII in subject info
raw.info['subject_info'] = {'first_name': 'Jane', 'last_name': 'Doe'}
```

**Security considerations:**
- MNE's `raw.anonymize()` strips dates and patient info from FIF files. Always call it before sharing.
- EDF files have patient headers that persist through MNE reads. Check with `/bci anonymize`.
- Training pipelines should verify data source integrity. Poisoned epochs corrupt classifiers.

### pynwb (Neurodata Without Borders)

**SDK:** pynwb
**Format:** NWB (HDF5-based)
**What the scanner detects:**

```python
# Rule 7: Subject metadata PII
nwbfile = pynwb.NWBFile(
    subject=pynwb.file.Subject(
        subject_id='Jane Doe',      # PII — flagged
        date_of_birth=datetime(...), # PII — flagged
        description='ADHD patient'   # Clinical info — flagged
    )
)

# Rule 7: NWB write
io = pynwb.NWBHDF5IO('output.nwb', 'w')
io.write(nwbfile)
```

**Security considerations:**
- NWB files on DANDI Archive are publicly accessible. Ensure all Subject fields are anonymized before upload.
- NWB's HDF5 format does not encrypt data at rest. Use filesystem-level encryption for sensitive recordings.
- The `.nwb` extension triggers the consent gate — confirm data governance before scanning.

### Emotiv (EPOC, Insight, EPOC X)

**SDK:** CortexPy (Cortex API v2)
**Connection:** Cloud API (WebSocket), BLE
**What the scanner detects:**

```python
# Rule 3: Hardcoded credentials
cortex = Cortex(client_id='abc', client_secret='xyz')  # Flagged

# Rule 1: Cloud data stream
cortex.subscribe(['eeg', 'mot', 'met'])
# 'met' = mental state stream — cognitive state capture (Rule 4, PII-011)
```

**Security considerations:**
- Emotiv's Cortex API requires cloud authentication. Never hardcode credentials.
- The `met` (mental metrics) stream outputs cognitive state scores. This constitutes cognitive state classification under neurorights frameworks.
- Emotiv processes data through their cloud. Verify their DPA covers your jurisdiction's requirements.

### Lab Streaming Layer (LSL)

**SDK:** pylsl, liblsl
**Protocol:** TCP/UDP multicast, zero encryption
**What the scanner detects:**

```python
# Rule 1: Unencrypted stream
from pylsl import StreamOutlet, StreamInlet, StreamInfo
outlet = StreamOutlet(info)  # Flagged — LSL has zero encryption
inlet = StreamInlet(results[0])

# Rule 7: XDF recording
# .xdf file writes are checked for PII in filenames
```

**Security considerations:**
- LSL is designed for lab environments, not production deployment. It has zero built-in encryption, authentication, or access control.
- Anyone on the local network can discover and subscribe to LSL streams via multicast.
- For production use, wrap LSL in TLS via stunnel or switch to BrainFlow's encrypted WebSocket.
- LSL's discoverable multicast means your neural data streams are visible to all network participants.

## General Integration Checklist

Before deploying any BCI integration:

- [ ] Run `/bci anonymize .` on all neural data files
- [ ] Run `/bci-scan .` on your codebase
- [ ] Run `/bci compliance scan .` for regulatory assessment
- [ ] Verify transport encryption (TLS/encrypted WebSocket)
- [ ] Verify data-at-rest encryption for neural recordings
- [ ] Confirm consent mechanisms are in place
- [ ] Have your security team review scan findings
- [ ] Have your compliance team review regulatory findings
- [ ] For clinical use: verify FDA/EU MDR/IEC requirements with regulatory affairs

## What the Plugin Cannot Check

The plugin scans code. It cannot verify:

- Hardware security (physical tamper resistance, secure element, shielding)
- Network segmentation (whether the BCI is on an isolated VLAN)
- Firmware integrity (whether device firmware is signed and verified)
- RF environment (whether the radio environment is monitored)
- Organizational controls (access policies, training, incident response procedures)

These require hands-on security assessment by qualified professionals.

---

*This guide covers community-supported integrations. QInnovate is not affiliated with OpenBCI, BrainFlow, MNE, NWB/DANDI, Emotiv, or any device manufacturer referenced. Device names are trademarks of their respective owners.*
