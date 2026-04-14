curl -s -X POST http://127.0.0.1:5000/api/subscriber/imsi-208930000000001/20893 \
  -H "Content-Type: application/json" \
  -b /tmp/cookies.txt \
  -d '{
    "plmnID": "20893",
    "ueId": "imsi-208930000000001",
    "AuthenticationSubscription": {
      "authenticationMethod": "5G_AKA",
      "permanentKey": {
        "permanentKeyValue": "8baf473f2f8fd09487cccbd7097c6862",
        "encryptionKey": 0,
        "encryptionAlgorithm": 0
      },
      "sequenceNumber": "000000000023",
      "authenticationManagementField": "8000",
      "milenage": {
        "op": {
          "opValue": "",
          "encryptionKey": 0,
          "encryptionAlgorithm": 0
        }
      },
      "opc": {
        "opcValue": "8e27b6af0e692e750f32667a3b14605d",
        "encryptionKey": 0,
        "encryptionAlgorithm": 0
      }
    },
    "AccessAndMobilitySubscriptionData": {
      "gpsis": ["msisdn-0900000000"],
      "subscribedUeAmbr": {
        "uplink": "1 Gbps",
        "downlink": "2 Gbps"
      },
      "nssai": {
        "defaultSingleNssais": [{
          "sst": 1,
          "sd": "010203"
        }]
      }
    },
    "SessionManagementSubscriptionData": [{
      "singleNssai": {"sst": 1, "sd": "010203"},
      "dnnConfigurations": {
        "internet": {
          "sscModes": {
            "defaultSscMode": "SSC_MODE_1",
            "allowedSscModes": ["SSC_MODE_2", "SSC_MODE_3"]
          },
          "pduSessionTypes": {
            "defaultSessionType": "IPV4",
            "allowedSessionTypes": ["IPV4"]
          },
          "sessionAmbr": {
            "uplink": "200 Mbps",
            "downlink": "100 Mbps"
          },
          "5gQosProfile": {
            "5qi": 9,
            "arp": {"priorityLevel": 8},
            "priorityLevel": 8
          }
        }
      }
    }]
  }'