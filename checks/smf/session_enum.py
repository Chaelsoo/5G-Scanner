from checks.base_check import BaseCheck, CheckResult
from core import http_client, token_manager
from config import SMF_URL, MCC, MNC, SUPI_START

class SMFSessionEnumCheck(BaseCheck):
    check_id = "CHECK-007"
    name = "SMF Session Enumeration"
    affected_nf = "SMF"
    endpoint = "GET /nsmf-pdusession/v1/sm-contexts"
    severity = "HIGH"

    def run(self) -> CheckResult:
        token = token_manager.get_token("SMF", "nsmf-pdusession")

        supi = f"imsi-{MCC}{MNC}{str(SUPI_START).zfill(10)}"
        url = f"{SMF_URL}/nsmf-pdusession/v1/sm-contexts/{supi}"

        request = {
            "method": "GET",
            "url": url,
            "headers": {"Authorization": "Bearer <rogue AMF token scoped for nsmf-pdusession>"}
        }

        if not token:
            return self.result(
                status="ERROR",
                request=request,
                response={},
                evidence="Could not obtain token from NRF",
                conclusion="Token request failed — cannot test session enumeration."
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
                    evidence=f"SMF returned active session data for {supi} to rogue NF",
                    conclusion="SMF does not verify that the requesting NF is authorized "
                               "for this specific session. Active session data, IP addresses, "
                               "and QoS parameters exposed to any rogue NF."
                )
            elif resp.status_code == 403:
                return self.result(
                    status="PATCHED",
                    request=request,
                    response=response,
                    evidence="SMF returned 403 — unauthorized access blocked",
                    conclusion="SMF enforces per-session authorization."
                )
            elif resp.status_code == 404:
                return self.result(
                    status="REQUIRES_UE",
                    request=request,
                    response=response,
                    evidence="No active PDU session found in SMF",
                    conclusion="CHECK-007 requires an active PDU session. "
                               "No real UE connected — cannot fully evaluate. "
                               "Run with a UE simulator to complete this check."
                )
            else:
                return self.result(
                    status="ERROR",
                    request=request,
                    response=response,
                    evidence=f"Unexpected status code {resp.status_code}",
                    conclusion="Unexpected response from SMF."
                )
        except Exception as e:
            return self.result(
                status="ERROR",
                request=request,
                response={},
                evidence=str(e),
                conclusion="Could not reach SMF."
            )