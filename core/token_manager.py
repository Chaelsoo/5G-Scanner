import httpx
from config import NRF_URL, ROGUE_NF_ID, ROGUE_NF_TYPE

_token_cache: dict = {}

def get_token(target_nf_type: str, scope: str) -> str | None:
    cache_key = f"{target_nf_type}:{scope}"
    if cache_key in _token_cache:
        return _token_cache[cache_key]

    url = f"{NRF_URL}/oauth2/token"
    data = {
        "grant_type": "client_credentials",
        "nfInstanceId": ROGUE_NF_ID,
        "nfType": ROGUE_NF_TYPE,
        "targetNfType": target_nf_type,
        "scope": scope
    }

    try:
        with httpx.Client(verify=False, timeout=10) as client:
            resp = client.post(
                url,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"}
            )
            if resp.status_code == 200:
                token = resp.json().get("access_token")
                if token:
                    _token_cache[cache_key] = token
                    return token
        return None
    except Exception as e:
        print(f"[token_manager] Error getting token: {e}")
        return None

def clear_cache():
    _token_cache.clear()