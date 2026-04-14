from checks.base_check import BaseCheck, CheckResult
from core import http_client
from config import NRF_URL

class NRFEnumCheck(BaseCheck):
    check_id = "CHECK-001"
    name = "Unauthenticated NRF Enumeration"
    affected_nf = "NRF"
    endpoint = "GET /nnrf-nfm/v1/nf-instances"
    severity = "HIGH"

    def run(self) -> CheckResult:
        url = f"{NRF_URL}/nnrf-nfm/v1/nf-instances"
        
        try:
            resp = http_client.get(url)
            
            request = {
                "method": "GET",
                "url": url,
                "headers": {"Authorization": "none"}
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
                    evidence="NRF returned NF list with no authentication",
                    conclusion="NRF does not enforce OAuth on enumeration endpoint. "
                               "Full network map accessible without credentials."
                )
            elif resp.status_code == 401:
                return self.result(
                    status="PATCHED",
                    request=request,
                    response=response,
                    evidence="NRF returned 401 Unauthorized",
                    conclusion="OAuth enforcement active. "
                               "Unauthenticated enumeration blocked."
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
                request={"method": "GET", "url": url},
                response={},
                evidence=str(e),
                conclusion="Could not reach NRF."
            )