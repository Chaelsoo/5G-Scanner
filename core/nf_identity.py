import uuid
from config import ROGUE_NF_ID, ROGUE_NF_TYPE, ROGUE_NF_IP, NRF_URL

def get_rogue_nf_profile() -> dict:
    return {
        "nfInstanceId": ROGUE_NF_ID,
        "nfType": ROGUE_NF_TYPE,
        "nfStatus": "REGISTERED",
        "ipv4Addresses": [ROGUE_NF_IP],
        "allowedNfTypes": ["AMF", "SMF", "UDM", "AUSF", "PCF", "NRF"],
        "nfServices": [
            {
                "serviceInstanceId": str(uuid.uuid4()),
                "serviceName": "namf-comm",
                "versions": [{"apiVersionInUri": "v1", "apiFullVersion": "1.0.0"}],
                "scheme": "http",
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": ROGUE_NF_IP, "port": 8000}]
            }
        ]
    }

def get_nf_instance_id() -> str:
    return ROGUE_NF_ID

def get_nf_type() -> str:
    return ROGUE_NF_TYPE