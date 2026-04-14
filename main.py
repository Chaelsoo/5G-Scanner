import argparse
from datetime import datetime, timezone
from rich.console import Console
from rich.table import Table
from rich import print as rprint

from core import nf_identity, http_client, token_manager
from config import NRF_URL

from checks.nrf.enum import NRFEnumCheck
from checks.nrf.rogue_registration import RogueNFRegistrationCheck
from checks.oauth.cross_token import CrossTokenCheck
from checks.udm.subscriber_enum import UDMSubscriberEnumCheck
from checks.amf.ue_context import AMFUEContextCheck
from checks.ausf.auth_vector import AUSFAuthVectorCheck
from checks.smf.session_enum import SMFSessionEnumCheck
from checks.pcf.policy_access import PCFPolicyAccessCheck

console = Console()

ALL_CHECKS = [
    NRFEnumCheck,
    RogueNFRegistrationCheck,
    CrossTokenCheck,
    UDMSubscriberEnumCheck,
    AMFUEContextCheck,
    AUSFAuthVectorCheck,
    SMFSessionEnumCheck,
    PCFPolicyAccessCheck,
]

STATUS_COLORS = {
    "VULNERABLE":   "bold red",
    "PATCHED":      "bold green",
    "PARTIAL":      "bold yellow",
    "REQUIRES_UE":  "bold blue",
    "ERROR":        "bold magenta",
}

def print_banner():
    console.print("""
[bold cyan]
  ███████╗ ██████╗      ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
  ██╔════╝██╔════╝      ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
  ███████╗██║  ███╗     ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
  ╚════██║██║   ██║     ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
  ███████║╚██████╔╝     ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
  ╚══════╝ ╚═════╝      ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
[/bold cyan]
[bold white]  5G Core SBI Security Scanner[/bold white]
[dim]  Targeting: {nrf}[/dim]
""".format(nrf=NRF_URL))

def run_scan(config, check_id=None):
    print_banner()
    console.print(f"[bold]Starting scan against {NRF_URL}[/bold]\n")

    # Step 1 — register rogue NF first
    console.print("[*] Registering rogue NF with NRF...")
    profile = nf_identity.get_rogue_nf_profile()
    nf_id = nf_identity.get_nf_instance_id()
    url = f"{NRF_URL}/nnrf-nfm/v1/nf-instances/{nf_id}"
    resp = http_client.put(url, json=profile)
    if resp.status_code in [200, 201]:
        console.print("[green][+] Rogue NF registered successfully[/green]")
    else:
        console.print(f"[yellow][!] Rogue NF registration returned {resp.status_code} — some checks may fail[/yellow]")

    # Step 2 — run checks
    results = []
    checks_to_run = ALL_CHECKS

    if check_id:
        checks_to_run = [c for c in ALL_CHECKS if c.check_id == check_id]
        if not checks_to_run:
            console.print(f"[red]Check {check_id} not found[/red]")
            return

    console.print(f"\n[bold]Running {len(checks_to_run)} checks...[/bold]\n")

    for CheckClass in checks_to_run:
        check = CheckClass(config={})
        console.print(f"[*] {check.check_id} — {check.name}...")
        result = check.run()
        results.append(result)
        color = STATUS_COLORS.get(result.status, "white")
        console.print(f"    [{color}]{result.status}[/{color}]")

    # Step 3 — print summary table
    print_summary(results)

    # Step 4 — save report
    save_report(results)

def print_summary(results):
    console.print("\n[bold]── Scan Summary ──────────────────────────────[/bold]\n")

    table = Table(show_header=True, header_style="bold white")
    table.add_column("Check", style="dim", width=12)
    table.add_column("Name", width=35)
    table.add_column("NF", width=8)
    table.add_column("Severity", width=10)
    table.add_column("Status", width=14)

    for r in results:
        color = STATUS_COLORS.get(r.status, "white")
        table.add_row(
            r.check_id,
            r.name,
            r.affected_nf,
            r.severity,
            f"[{color}]{r.status}[/{color}]"
        )

    console.print(table)

    vulnerable = [r for r in results if r.status == "VULNERABLE"]
    patched    = [r for r in results if r.status == "PATCHED"]
    requires   = [r for r in results if r.status == "REQUIRES_UE"]
    errors     = [r for r in results if r.status == "ERROR"]

    console.print(f"\n  [bold red]VULNERABLE : {len(vulnerable)}[/bold red]")
    console.print(f"  [bold green]PATCHED    : {len(patched)}[/bold green]")
    console.print(f"  [bold blue]REQUIRES_UE: {len(requires)}[/bold blue]")
    console.print(f"  [bold magenta]ERROR      : {len(errors)}[/bold magenta]")

def save_report(results):
    import json

    report = {
        "tool": "5GProbe",
        "target": NRF_URL,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "findings": [
            {
                "check_id": r.check_id,
                "name": r.name,
                "status": r.status,
                "affected_nf": r.affected_nf,
                "endpoint": r.endpoint,
                "evidence": r.evidence,
                "conclusion": r.conclusion,
                "request": r.request,
                "response": r.response
            }
            for r in results
        ]
    }

    with open("report/report.json", "w") as f:
        json.dump(report, f, indent=2)

    console.print(f"\n[dim]Report saved to report/report.json[/dim]")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="5GProbe — 5G Core SBI Security Scanner")
    parser.add_argument("--nrf", default=None, help="NRF address (overrides config)")
    parser.add_argument("--mode", choices=["scan", "attack"], default="scan")
    parser.add_argument("--check", default=None, help="Run specific check e.g. CHECK-001")
    args = parser.parse_args()

    if args.mode == "scan":
        run_scan(config={}, check_id=args.check)
    elif args.mode == "attack":
        console.print("[yellow]Attack mode not yet implemented[/yellow]")