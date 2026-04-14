import argparse
from rich.console import Console
from rich.table import Table
from rich import print as rprint
from datetime import datetime, timezone

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

from attacks.nrf.rogue_nf import RogueNFAttack
from attacks.udm.subscriber_dump import UDMSubscriberDumpAttack
from attacks.ausf.auth_vector import AUSFAuthVectorAttack
from attacks.pcf.policy_abuse import PCFPolicyAbuseAttack

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

ALL_ATTACKS = {
    "nrf":        RogueNFAttack,
    "udm":        UDMSubscriberDumpAttack,
    "ausf":       AUSFAuthVectorAttack,
    "pcf":        PCFPolicyAbuseAttack,
}

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

def register_rogue_nf():
    profile = nf_identity.get_rogue_nf_profile()
    nf_id = nf_identity.get_nf_instance_id()
    url = f"{NRF_URL}/nnrf-nfm/v1/nf-instances/{nf_id}"
    resp = http_client.put(url, json=profile)
    return resp.status_code in [200, 201]

def run_scan(check_id=None, nf=None):
    print_banner()
    console.print(f"[bold]Starting scan against {NRF_URL}[/bold]\n")

    console.print("[*] Registering rogue NF with NRF...")
    if register_rogue_nf():
        console.print("[green][+] Rogue NF registered successfully[/green]")
    else:
        console.print("[yellow][!] Rogue NF registration failed — some checks may fail[/yellow]")

    checks_to_run = ALL_CHECKS

    if check_id:
        checks_to_run = [c for c in ALL_CHECKS if c.check_id == check_id]
        if not checks_to_run:
            console.print(f"[red]Check {check_id} not found[/red]")
            return

    if nf:
        checks_to_run = [c for c in checks_to_run if c.affected_nf.upper() == nf.upper()]
        if not checks_to_run:
            console.print(f"[red]No checks found for NF '{nf}'[/red]")
            console.print(f"Available NFs: NRF, UDM, AMF, AUSF, SMF, PCF")
            return
        console.print(f"[dim]Filtering checks for NF: {nf.upper()}[/dim]")

    console.print(f"\n[bold]Running {len(checks_to_run)} checks...[/bold]")

    results = []
    for CheckClass in checks_to_run:
        check = CheckClass(config={})
        result = check.run()
        results.append(result)
        print_check_detail(result)

    print_scan_summary(results)
    save_scan_report(results)

def run_attack(module=None):
    print_banner()
    console.print(f"[bold red]Attack mode — targeting {NRF_URL}[/bold red]\n")

    console.print("[*] Registering rogue NF with NRF...")
    if register_rogue_nf():
        console.print("[green][+] Rogue NF registered successfully[/green]\n")
    else:
        console.print("[yellow][!] Rogue NF registration failed — attacks may fail[/yellow]\n")

    if module == "all":
        attacks_to_run = list(ALL_ATTACKS.values())
    elif module in ALL_ATTACKS:
        attacks_to_run = [ALL_ATTACKS[module]]
    else:
        console.print(f"[red]Attack module '{module}' not found.[/red]")
        console.print(f"Available: {', '.join(ALL_ATTACKS.keys())}, all")
        return

    results = []
    for AttackClass in attacks_to_run:
        attack = AttackClass()
        console.print(f"[bold red][*] {attack.attack_id} — {attack.name}[/bold red]")
        result = attack.run()
        results.append(result)

        if result.success:
            console.print(f"[bold red][+] SUCCESS[/bold red]")
        else:
            console.print(f"[yellow][-] FAILED[/yellow]")

        console.print(f"    Evidence : {result.evidence}")
        console.print(f"    Conclusion: {result.conclusion}")

        if result.data:
            console.print(f"    Data:")
            for k, v in result.data.items():
                if isinstance(v, dict) and len(str(v)) > 200:
                    console.print(f"      {k}: [{len(v)} entries]")
                else:
                    console.print(f"      {k}: {v}")
        console.print()

    print_attack_summary(results)
    save_attack_report(results)

def print_scan_summary(results):
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

def print_attack_summary(results):
    console.print("\n[bold]── Attack Summary ──────────────────────────────[/bold]\n")

    table = Table(show_header=True, header_style="bold white")
    table.add_column("Attack", style="dim", width=12)
    table.add_column("Name", width=40)
    table.add_column("NF", width=8)
    table.add_column("Result", width=10)

    for r in results:
        color = "bold red" if r.success else "yellow"
        status = "SUCCESS" if r.success else "FAILED"
        table.add_row(
            r.attack_id,
            r.name,
            r.affected_nf,
            f"[{color}]{status}[/{color}]"
        )

    console.print(table)

    success = [r for r in results if r.success]
    failed  = [r for r in results if not r.success]

    console.print(f"\n  [bold red]SUCCESS: {len(success)}[/bold red]")
    console.print(f"  [yellow]FAILED : {len(failed)}[/yellow]")

def print_check_detail(result):
    status_color = STATUS_COLORS.get(result.status, "white")

    console.print(f"\n[bold white]{'─' * 60}[/bold white]")
    console.print(f"[bold]{result.check_id}[/bold] — [bold white]{result.name}[/bold white]")
    console.print(f"  NF       : [cyan]{result.affected_nf}[/cyan]")
    console.print(f"  Endpoint : [dim]{result.endpoint}[/dim]")
    console.print(f"  Severity : [yellow]{result.severity}[/yellow]")
    console.print()

    # Response only
    console.print(f"  [bold]Response:[/bold]")
    resp = result.response
    status_code = resp.get('status_code', 'N/A')
    code_color = "green" if str(status_code).startswith('2') else "red"
    console.print(f"    HTTP [{code_color}]{status_code}[/{code_color}]")
    if resp.get('body'):
        console.print(f"    Body: [dim]{resp['body']}[/dim]")

    console.print()

    # Result
    console.print(f"  [bold]Result:[/bold]")
    console.print(f"    Status     : [{status_color}]{result.status}[/{status_color}]")
    console.print(f"    Evidence   : {result.evidence}")
    console.print(f"    Conclusion : [italic]{result.conclusion}[/italic]")
    
def save_scan_report(results):
    import json
    report = {
        "tool": "5G Scanner",
        "mode": "scan",
        "target": NRF_URL,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "findings": [
            {
                "check_id":   r.check_id,
                "name":       r.name,
                "status":     r.status,
                "severity":   r.severity,
                "affected_nf": r.affected_nf,
                "endpoint":   r.endpoint,
                "evidence":   r.evidence,
                "conclusion": r.conclusion,
                "request":    r.request,
                "response":   r.response
            }
            for r in results
        ]
    }
    with open("report/report.json", "w") as f:
        json.dump(report, f, indent=2)
    console.print(f"\n[dim]Report saved to report/report.json[/dim]")

def save_attack_report(results):
    import json
    report = {
        "tool": "5G Scanner",
        "mode": "attack",
        "target": NRF_URL,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "results": [
            {
                "attack_id":  r.attack_id,
                "name":       r.name,
                "affected_nf": r.affected_nf,
                "endpoint":   r.endpoint,
                "success":    r.success,
                "evidence":   r.evidence,
                "conclusion": r.conclusion,
                "data":       r.data
            }
            for r in results
        ]
    }
    with open("report/attack_report.json", "w") as f:
        json.dump(report, f, indent=2)
    console.print(f"\n[dim]Attack report saved to report/attack_report.json[/dim]")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="5G Scanner — 5G Core SBI Security Scanner")
    parser.add_argument("--mode", choices=["scan", "attack"], default="scan")
    parser.add_argument("--check", default=None, help="Run specific check e.g. CHECK-001")
    parser.add_argument("--nf", default=None, help="Scan specific NF e.g. UDM, AMF, AUSF, NRF, PCF, SMF")
    parser.add_argument("--module", default="all", help="Attack module: nrf, udm, ausf, pcf, all")
    args = parser.parse_args()

    if args.mode == "scan":
        run_scan(check_id=args.check, nf=args.nf)
    elif args.mode == "attack":
        run_attack(module=args.module)