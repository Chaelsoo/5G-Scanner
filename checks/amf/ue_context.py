from checks.base_check import BaseCheck, CheckResult
from core import http_client, token_manager
from config import AMF_URL, MCC, MNC, SUPI_START

class AMFUEContextCheck(BaseCheck):
    check_id = "CHECK-005"
    name = "AMF UE Context Unauthorized Access"
    affected_nf = "AMF"
    endpoint = "GET /namf-comm/v1/ue-contexts/{ueContextId}"
    severity = "CRITICAL"

    def run(self) -> CheckResult:
        token = token_manager.get_token("AMF", "namf-comm")

        supi = f"imsi-{MCC}{MNC}{str(SUPI_START).zfill(10)}"
        url = f"{AMF_URL}/namf-comm/v1/ue-contexts/{supi}"

        request = {
            "method": "GET",
            "url": url,
            "headers": {"Authorization": "Bearer <rogue SMF token scoped for namf-comm>"}
        }

        if not token:
            return self.result(
                status="ERROR",
                request=request,
                response={},
                evidence="Could not obtain token from NRF",
                conclusion="Token request failed — cannot test UE context access."
            )

        try:
            resp = http_client.get(url, token=token)

            response = {
                "status_code": resp.status_code,
                "body": resp.text[:500]
            }

            if resp.status_code == 200:
                return self.result(
                    status="VULNERABLE",
                    request=request,
                    response=response,
                    evidence=f"AMF returned UE context for {supi} to rogue NF",
                    conclusion="AMF does not verify that the requesting NF is authorized "
                               "for this specific UE. Real-time location, session state, "
                               "and security keys exposed to any rogue NF."
                )
            elif resp.status_code == 403:
                return self.result(
                    status="PATCHED",
                    request=request,
                    response=response,
                    evidence="AMF returned 403 — unauthorized access blocked",
                    conclusion="AMF enforces per-UE authorization."
                )
            elif resp.status_code == 404:
                return self.result(
                    status="REQUIRES_UE",
                    request=request,
                    response=response,
                    evidence="No active UE context found in AMF",
                    conclusion="CHECK-005 requires an active UE registration. "
                               "No real UE connected — cannot fully evaluate. "
                               "Run with a UE simulator to complete this check."
                )
            else:
                return self.result(
                    status="ERROR",
                    request=request,
                    response=response,
                    evidence=f"Unexpected status code {resp.status_code}",
                    conclusion="Unexpected response from AMF."
                )
        except Exception as e:
            return self.result(
                status="ERROR",
                request=request,
                response={},
                evidence=str(e),
                conclusion="Could not reach AMF."
            )