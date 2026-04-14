# 5G Scanner

A modular security scanner and attack framework targeting 5G Core Service Based Interface (SBI) APIs.

Built as part of a WiFi/Networking security research project at ESI SBA.

---

## What it does

5G Scanner probes and attacks the internal REST APIs (SBI) that 5G Core Network Functions (NFs) use to communicate with each other. It impersonates a legitimate NF, obtains OAuth2 tokens from the NRF, and systematically tests each NF for access control weaknesses.

---

## Background

5G Core uses a Service Based Architecture (SBA) where microservices called Network Functions (NFs) communicate over HTTP/2 REST APIs — the Service Based Interface (SBI). OAuth2 is used for access control between NFs.

The key weakness: **OAuth2 verifies NF identity but not authorization context.** Any registered NF with a valid token can query any subscriber's data regardless of whether it's legitimately serving that subscriber.

This tool demonstrates that weakness against free5GC — an open source 5G Core implementation used in research, private 5G deployments, and commercial products.

---

## Architecture
5G Scanner
├── core/               # HTTP client, NF identity, token management
├── checks/             # Automated scan modules (non-destructive)
│   ├── nrf/           
│   ├── oauth/          
│   ├── udm/            
│   ├── amf/            
│   ├── ausf/           
│   ├── smf/            
│   └── pcf/            
├── attacks/            # Manual attack modules (explicit, targeted)
│   ├── nrf/            # Rogue NF registration + token acquisition
│   ├── udm/            # Full subscriber dump
│   ├── ausf/           # Auth vector harvesting
│   └── pcf/            # Policy abuse
└── report/             # JSON report + network map visualizer

---

## Checks                           

| NF | Description | Status (free5GC v4.2.1) |
|----|-------------|--------------------------|
| NRF | Unauthenticated enumeration | PATCHED |
| NRF | Rogue NF registration | VULNERABLE |
| OAuth | Cross-service token abuse | PATCHED |
| UDM | Subscriber enumeration | VULNERABLE |
| AMF | UE context unauthorized access | REQUIRES_UE |
| AUSF | Auth vector harvesting | VULNERABLE |
| SMF | Session enumeration | REQUIRES_UE |
| PCF | Policy unauthorized access | VULNERABLE |

---

## Attacks

| Attack | NF | What it does                                |
|--------|---|----------------------------------------------|
| NRF | Register fake AMF, acquire OAuth tokens for all NFs |
| UDM | Iterate SUPIs, extract full subscriber profiles |
| AUSF | Harvest 5G-AKA auth vectors (RAND, HXRES*, AUTN) |
| PCF | Register as policy consumer for all subscribers |

---

## Setup

**Requirements:**
- Python 3.10+
- free5GC v4.2.1 running on target (or any compliant 5G Core)
- SSH tunnel to target NFs

**Install:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install httpx PyJWT rich
```

**Configure:**

Edit `config.py` with your target NF addresses and tunnel ports.

---

## Usage

```bash
# Full automated scan
python3 main.py --mode scan

# Scan specific NF
python3 main.py --mode scan --nf UDM
python3 main.py --mode scan --nf AUSF

# Run all attacks
python3 main.py --mode attack --module all

# Run specific attack
python3 main.py --mode attack --module udm
python3 main.py --mode attack --module ausf
```

---

## Output

- Terminal — structured per-check output with response and conclusion
- `report/report.json` — full scan findings in JSON
- `report/attack_report.json` — attack results in JSON
- `report/network_map.html` — interactive network topology with vulnerability overlay

---

## Threat Model

Attacker has gained access to the internal 5G Core network (compromised container, insider, misconfigured cloud security group) and can reach the SBI endpoints directly.

This is realistic for:
- Private 5G deployments at enterprises (factories, hospitals, campuses)
- University research networks running free5GC/Open5GS
- Cloud deployments with misconfigured security groups
- Development/staging environments

---

## References

- Anqi Chen et al. — *Cross-Service Token: Finding Attacks in 5G Core Networks* — NDSS 2026
- 3GPP TS 33.501 — Security architecture and procedures for 5G system
- 3GPP TS 29.510 — Network function repository services
- free5GC — https://free5gc.org