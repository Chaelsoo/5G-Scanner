from checks.base_check import BaseCheck, CheckResult
from core import http_client, token_manager
from config import NRF_URL

class CrossTokenCheck(BaseCheck):
    check_id = "CHECK-003"
    name = "Cross-Service Token Abuse"
    affected_nf = "NRF"
    endpoint = "GET /nnrf-disc/v1/nf-instances"
    severity = "CRITICAL"

    def run(self) -> CheckResult:
        # Step 1 — get token scoped for UDM
        token = token_manager.get_token("UDM", "nudm-sdm")

        request_token = {
            "method": "POST",
            "url": f"{NRF_URL}/oauth2/token",
            "body": {
                "grant_type": "client_credentials",
                "targetNfType": "UDM",
                "scope": "nudm-sdm"
            }
        }

        if not token:
            return self.result(
                status="ERROR",
                request=request_token,
                response={},
                evidence="Could not obtain token from NRF",
                conclusion="Token request failed — cannot test cross-service abuse."
            )

        # Step 2 — use UDM-scoped token to call NRF discovery
        url = f"{NRF_URL}/nnrf-disc/v1/nf-instances"
        params = {"target-nf-type": "SMF"}

        try:
            resp = http_client.get(url, token=token, params=params)

            request = {
                "method": "GET",
                "url": url,
                "headers": {"Authorization": f"Bearer <token scoped for nudm-sdm>"},
                "note": "Token scoped for UDM used to call NRF discovery"
            }
            response = {
                "status_code": resp.status_code,
                "body": resp.text[:500]
            }

            if resp.status_code == 200:
                return self.result(
                    status="VULNERABLE",
                    request=request,
                    response=response,
                    evidence="NRF accepted UDM-scoped token for discovery service",
                    conclusion="Token scope is not enforced. A token issued for one "
                               "service can be used to access any other service. "
                               "Full privilege escalation via single token."
                )
            elif resp.status_code == 401:
                return self.result(
                    status="PATCHED",
                    request=request,
                    response=response,
                    evidence="NRF returned 401 — scope mismatch detected",
                    conclusion="Cross-service token abuse blocked in v4.2.1. "
                               "Scope enforcement is working correctly."
                )
            else:
                return self.result(
                    status="ERROR",
                    request=request,
                    response=response,
                    evidence=f"Unexpected status code {resp.status_code}",
                    conclusion="Unexpected response."
                )
        except Exception as e:
            return self.result(
                status="ERROR",
                request={"method": "GET", "url": url},
                response={},
                evidence=str(e),
                conclusion="Could not reach NRF discovery endpoint."
            )