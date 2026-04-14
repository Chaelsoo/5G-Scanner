from dataclasses import dataclass, field
from typing import Optional, Any

@dataclass
class AttackResult:
    attack_id: str
    name: str
    affected_nf: str
    endpoint: str
    success: bool
    data: Any          # extracted data
    evidence: str
    conclusion: str

class BaseAttack:
    attack_id: str = ""
    name: str = ""
    affected_nf: str = ""
    endpoint: str = ""

    def __init__(self, config={}):
        self.config = config

    def run(self) -> AttackResult:
        raise NotImplementedError

    def result(self, success, data, evidence, conclusion) -> AttackResult:
        return AttackResult(
            attack_id=self.attack_id,
            name=self.name,
            affected_nf=self.affected_nf,
            endpoint=self.endpoint,
            success=success,
            data=data,
            evidence=evidence,
            conclusion=conclusion
        )