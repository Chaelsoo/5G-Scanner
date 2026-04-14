import httpx
from config import TIMEOUT

def get_client() -> httpx.Client:
    return httpx.Client(
        verify=False,
        timeout=TIMEOUT
    )

def get(url: str, token: str = None, params: dict = None) -> httpx.Response:
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with get_client() as client:
        return client.get(url, headers=headers, params=params)

def post(url: str, token: str = None, json: dict = None) -> httpx.Response:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with get_client() as client:
        return client.post(url, headers=headers, json=json)

def put(url: str, token: str = None, json: dict = None) -> httpx.Response:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with get_client() as client:
        return client.put(url, headers=headers, json=json)

def patch(url: str, token: str = None, json: dict = None) -> httpx.Response:
    headers = {"Content-Type": "application/json-patch+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with get_client() as client:
        return client.patch(url, headers=headers, json=json)