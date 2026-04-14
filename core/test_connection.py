import httpx
from config import NRF_URL

def test_connection():
    print(f"[*] Testing connection to free5GC NRF at {NRF_URL}")
    
    try:
        with httpx.Client(http2=False, verify=False, timeout=10) as client:
            
            # Test 1 — unauthenticated request (expect 401)
            print("\n[1] Unauthenticated NRF enumeration...")
            resp = client.get(f"{NRF_URL}/nnrf-nfm/v1/nf-instances")
            print(f"    Status : {resp.status_code}")
            print(f"    Response: {resp.text[:200]}")
            if resp.status_code == 401:
                print("    [CHECK-001] OAuth enforced — unauthenticated access blocked")
            elif resp.status_code == 200:
                print("    [CHECK-001] VULNERABLE — unauthenticated access allowed")

            # Test 2 — token endpoint
            print("\n[2] Token endpoint reachability...")
            resp2 = client.post(f"{NRF_URL}/oauth2/token")
            print(f"    Status : {resp2.status_code}")
            print(f"    Response: {resp2.text[:200]}")

            # Test 3 — NRF discovery endpoint
            print("\n[3] NRF discovery endpoint...")
            resp3 = client.get(f"{NRF_URL}/nnrf-disc/v1/nf-instances")
            print(f"    Status : {resp3.status_code}")
            print(f"    Response: {resp3.text[:200]}")

    except httpx.ConnectError:
        print("    [ERROR] Cannot reach NRF — is the tunnel open?")
    except Exception as e:
        print(f"    [ERROR] {e}")

if __name__ == "__main__":
    test_connection()