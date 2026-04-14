NRF_HOST = "localhost"
NRF_PORT = 9000
NRF_URL  = f"http://{NRF_HOST}:{NRF_PORT}"

# NF addresses (via SSH tunnel — add separate tunnels per NF)
UDM_URL  = "http://localhost:9003"
AMF_URL  = "http://localhost:9018"
AUSF_URL = "http://localhost:9009"
SMF_URL  = "http://localhost:9002"
PCF_URL  = "http://localhost:9007"

# Rogue NF identity
ROGUE_NF_ID   = "12345678-1234-1234-1234-123456789012"
ROGUE_NF_TYPE = "AMF"
ROGUE_NF_IP   = "127.0.0.99"

# Timeouts
TIMEOUT = 10

# SUPI range
MCC        = "208"
MNC     = "93"
MNC_PAD = "093"
SUPI_START = 1
SUPI_END   = 20