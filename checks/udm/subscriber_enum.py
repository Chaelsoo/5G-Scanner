from checks.base_check import BaseCheck, CheckResult
from core import http_client, token_manager
from config import UDM_URL, MCC, MNC, SUPI_START

class UDMSubscriberEnumCheck(BaseCheck):
    check_id = "CHECK-004"
    name = "UDM Subscriber Enumeration"
    affected_nf = "UDM"
    endpoint = "GET /nudm-sdm/v2/{supi}/am-data"
    severity = "CRITICAL"

    def run(self) -> CheckResult:
        token = token_manager.get_token("UDM", "nudm-sdm")

        supi = f"imsi-{MCC}{MNC}{str(SUPI_START).zfill(10)}"
        url = f"{UDM_URL}/nudm-sdm/v2/{supi}/am-data"
        params = {"plmn-id": f'{{"mcc":"{MCC}","mnc":"{MNC}"}}'}

        request = {
            "method": "GET",
            "url": url,
            "params": params,
            "headers": {"Authorization": "Bearer <rogue AMF token scoped for nudm-sdm>"}
        }

        if not token:
            return self.result(
                status="ERROR",
                request=request,
                response={},
                evidence="Could not obtain token from NRF",
                conclusion="Token request failed — cannot test subscriber enumeration."
            )

        try:
            resp = http_client.get(url, token=token, params=params)

            response = {
                "status_code": resp.status_code,
                "body": resp.text[:500]
            }

            if resp.status_code == 200:
                return self.result(
                    status="VULNERABLE",
                    request=request,
                    response=response,
                    evidence=f"UDM returned subscriber profile for {supi} to rogue AMF",
                    conclusion="UDM does not verify that the requesting AMF is actually "
                               "serving this subscriber. Any NF with a valid token can "
                               "extract any subscriber's profile. Full subscriber database "
                               "extractable by iterating SUPIs."
                )
            elif resp.status_code == 403:
                return self.result(
                    status="PATCHED",
                    request=request,
                    response=response,
                    evidence="UDM returned 403 — unauthorized access blocked",
                    conclusion="UDM enforces per-subscriber authorization."
                )
            elif resp.status_code == 404:
                return self.result(
                    status="ERROR",
                    request=request,
                    response=response,
                    evidence="Subscriber not found in UDM",
                    conclusion="No subscriber data to test against. Add a subscriber first."
                )
            else:
                return self.result(
                    status="ERROR",
                    request=request,
                    response=response,
                    evidence=f"Unexpected status code {resp.status_code}",
                    conclusion="Unexpected response from UDM."
                )
        except Exception as e:
            return self.result(
                status="ERROR",
                request=request,
                response={},
                evidence=str(e),
                conclusion="Could not reach UDM."
            )