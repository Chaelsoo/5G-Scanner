from dataclasses import dataclass, field
from typing import Optional

@dataclass
class CheckResult:
    check_id: str
    name: str
    status: str 
    affected_nf: str
    endpoint: str
    request: dict
    response: dict
    severity: str
    evidence: str
    conclusion: str

class BaseCheck:
    check_id: str = ""
    name: str = ""
    affected_nf: str = ""
    endpoint: str = ""
    severity: str = "" 

    def __init__(self, config):
        self.config = config

    def run(self) -> CheckResult:
        raise NotImplementedError

    def result(self, status, request, response, evidence, conclusion) -> CheckResult:
        return CheckResult(
            check_id=self.check_id,
            name=self.name,
            status=status,
            affected_nf=self.affected_nf,
            endpoint=self.endpoint,
            request=request,
            response=response,
            severity=self.severity,
            evidence=evidence,
            conclusion=conclusion
        )