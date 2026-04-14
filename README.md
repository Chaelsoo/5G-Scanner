# 5G Scanner

A modular security scanner and attack framework targeting 5G Core Service Based Interface (SBI) APIs.

## What it does

5G Scanner probes and attacks the internal REST APIs that 5G Core Network Functions use to communicate with each other. It impersonates a legitimate NF, obtains OAuth2 tokens from the NRF, and systematically tests each NF for access control weaknesses.

## Background

5G Core uses a Service Based Architecture where microservices called Network Functions communicate over HTTP/2 REST APIs called the Service Based Interface. OAuth2 is used for access control between NFs.

The key weakness: OAuth2 verifies NF identity but not authorization context. Any registered NF with a valid token can query any subscriber's data regardless of whether it is legitimately serving that subscriber.

This tool demonstrates that weakness against free5GC, an open source 5G Core implementation used in research, private 5G deployments, and commercial products.

## Project Structure

~~~
5G Scanner
├── core/          HTTP client, NF identity, token management
├── checks/        Automated scan modules
│   ├── nrf/       Unauthenticated enumeration, rogue NF registration
│   ├── oauth/     Cross-service token abuse
│   ├── udm/       Subscriber enumeration
│   ├── amf/       UE context unauthorized access
│   ├── ausf/      Auth vector harvesting
│   ├── smf/       Session enumeration
│   └── pcf/       Policy unauthorized access
├── attacks/       Manual attack modules
│   ├── nrf/       Rogue NF registration and token acquisition
│   ├── udm/       Full subscriber dump
│   ├── ausf/      Auth vector harvesting
│   └── pcf/       Policy abuse
└── report/        JSON reports and network map visualizer
~~~

## Scan Modules

| NF | What is tested | Result on free5GC v4.2.1 |
|---|---|---|
| NRF | Unauthenticated enumeration | Patched |
| NRF | Rogue NF registration | Vulnerable |
| OAuth | Cross-service token scope enforcement | Patched |
| UDM | Subscriber data access with rogue token | Vulnerable |
| AMF | UE context access with rogue token | Requires active UE |
| AUSF | Authentication vector harvesting | Vulnerable |
| SMF | Session enumeration with rogue token | Requires active UE |
| PCF | Policy context creation with rogue token | Vulnerable |

## Attack Modules

| NF | What it does |
|---|---|
| NRF | Register fake AMF, acquire OAuth tokens for all NFs |
| UDM | Iterate SUPIs, extract full subscriber profiles |
| AUSF | Harvest 5G-AKA auth vectors |
| PCF | Register as policy consumer for all subscribers |

## Setup

Requirements: Python 3.10+, free5GC v4.2.1 or any compliant 5G Core, SSH tunnel if remote.

~~~bash
python3 -m venv venv
source venv/bin/activate
pip install httpx PyJWT rich
~~~

Configure `config.py` with your target NF addresses and tunnel ports.

## Usage

~~~bash
python3 main.py --mode scan
python3 main.py --mode scan --nf UDM
python3 main.py --mode attack --module all
python3 main.py --mode attack --module udm
~~~

## Output

After each run the tool produces:

- Terminal output with structured per-check results
- report/report.json with full scan findings
- report/attack_report.json with attack results
- report/network_map.html with interactive network topology

## Threat Model

Attacker has gained access to the internal 5G Core network through a compromised container, insider access, or misconfigured cloud security group, and can reach the SBI endpoints directly.

Realistic targets include private 5G deployments at enterprises, university research networks, cloud deployments with misconfigured security groups, and development environments.

## References

- Anqi Chen et al., Cross-Service Token: Finding Attacks in 5G Core Networks, NDSS 2026
- 3GPP TS 33.501, Security architecture and procedures for 5G system
- 3GPP TS 29.510, Network function repository services
- free5GC, https://free5gc.org