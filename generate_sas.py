#!/usr/bin/env python3
"""
generate_sas.py — Generate Azure IoT Hub SAS tokens (device- or service-level).

Works great on a Raspberry Pi (Python 3). No external deps.

Usage examples:

1) Using a device connection string (recommended for device SAS):
   python3 generate_sas.py \
     --connection-string "HostName=YourHub.azure-devices.net;DeviceId=myPi;SharedAccessKey=BASE64KEY==" \
     --ttl 3600

2) Using an IoT Hub policy connection string (service SAS):
   python3 generate_sas.py \
     --connection-string "HostName=YourHub.azure-devices.net;SharedAccessKeyName=iothubowner;SharedAccessKey=BASE64KEY==" \
     --ttl 3600

3) Supplying pieces manually (e.g., for a module):
   python3 generate_sas.py \
     --host YourHub.azure-devices.net \
     --device-id myPi \
     --module-id cam \
     --key BASE64KEY== \
     --policy-name iothubowner \
     --ttl 3600

The script prints the SAS token to stdout.
"""

import argparse
import base64
import hashlib
import hmac
import sys
import time
import urllib.parse
from typing import Optional, Tuple

def parse_connection_string(cs: str) -> dict:
    """Parse Azure IoT Hub/device connection string into a dict."""
    parts = {}
    for seg in cs.strip().split(";"):
        if not seg:
            continue
        if "=" not in seg:
            continue
        k, v = seg.split("=", 1)
        parts[k.strip()] = v.strip()
    return parts

def build_resource_uri(host: str, device_id: Optional[str], module_id: Optional[str]) -> str:
    """Construct the resource URI used in the SAS token's 'sr' field."""
    if not host:
        raise ValueError("Host name is required to build resource URI.")
    if device_id and module_id:
        path = f"{host}/devices/{device_id}/modules/{module_id}"
    elif device_id:
        path = f"{host}/devices/{device_id}"
    else:
        path = host  # service-level SAS (policy)
    # Lowercase host per IoT Hub guidance (the path part may remain case-sensitive for IDs).
    return path.lower()

def sign(key_b64: str, string_to_sign: str) -> str:
    """Return base64-encoded HMAC-SHA256 signature from a base64-encoded key."""
    try:
        key = base64.b64decode(key_b64, validate=True)
    except Exception as e:
        raise ValueError("SharedAccessKey must be a valid base64 string.") from e
    mac = hmac.new(key, msg=string_to_sign.encode("utf-8"), digestmod=hashlib.sha256)
    sig = base64.b64encode(mac.digest()).decode("utf-8")
    return sig

def build_sas(resource_uri: str,
              key_b64: str,
              expiry: int,
              policy_name: Optional[str] = None) -> str:
    """
    Build a SharedAccessSignature token.
    Format:
      SharedAccessSignature sr=<url-encoded-resource-uri>&sig=<url-encoded-signature>&se=<expiry>&skn=<policy>
    'skn' is included only if policy_name is provided (service-level tokens).
    """
    # String to sign: <lowercased-resource-uri>\n<expiry>
    string_to_sign = f"{urllib.parse.quote_plus(resource_uri)}\n{expiry}"
    signature = sign(key_b64, string_to_sign)
    token = (
        f"SharedAccessSignature sr={urllib.parse.quote_plus(resource_uri)}"
        f"&sig={urllib.parse.quote_plus(signature)}"
        f"&se={expiry}"
    )
    if policy_name:
        token += f"&skn={urllib.parse.quote_plus(policy_name)}"
    return token

def compute_expiry(ttl_seconds: int) -> int:
    """Compute expiry timestamp (epoch seconds) for ttl in seconds."""
    if ttl_seconds <= 0:
        raise ValueError("TTL must be a positive integer (seconds).")
    return int(time.time()) + int(ttl_seconds)

def infer_from_connection_string(cs_parts: dict) -> Tuple[str, Optional[str], Optional[str], Optional[str], str]:
    """
    Given parsed connection string parts, infer:
      host, device_id, module_id, policy_name, key_b64
    Raises on missing required values.
    """
    host = cs_parts.get("HostName")
    device_id = cs_parts.get("DeviceId")
    module_id = cs_parts.get("ModuleId")
    policy_name = cs_parts.get("SharedAccessKeyName")
    key_b64 = cs_parts.get("SharedAccessKey")
    if not host or not key_b64:
        raise ValueError("Connection string must contain HostName and SharedAccessKey.")
    return host, device_id, module_id, policy_name, key_b64

def main():
    parser = argparse.ArgumentParser(description="Generate Azure IoT Hub SAS token.")
    parser.add_argument("--connection-string", help="IoT Hub or device connection string.")
    parser.add_argument("--host", help="Hub host, e.g. YourHub.azure-devices.net")
    parser.add_argument("--device-id", help="DeviceId (for device-level SAS).")
    parser.add_argument("--module-id", help="ModuleId (optional).")
    parser.add_argument("--key", dest="key_b64", help="Base64 SharedAccessKey.")
    parser.add_argument("--policy-name", help="Policy name for service SAS (e.g., iothubowner).")
    parser.add_argument("--ttl", type=int, default=3600, help="Token lifetime in seconds (default: 3600).")
    parser.add_argument("--unix-expiry", type=int, help="Explicit expiry (epoch seconds). Overrides --ttl.")
    args = parser.parse_args()

    try:
        if args.connection_string:
            cs_parts = parse_connection_string(args.connection_string)
            host, device_id, module_id, policy_name, key_b64 = infer_from_connection_string(cs_parts)
            # Allow CLI flags to override CS pieces:
            host = args.host or host
            device_id = args.device_id or device_id
            module_id = args.module_id or module_id
            policy_name = args.policy_name or policy_name
            key_b64 = args.key_b64 or key_b64
        else:
            if not args.host or not args.key_b64:
                raise ValueError("Either --connection-string or both --host and --key are required.")
            host = args.host
            device_id = args.device_id
            module_id = args.module_id
            policy_name = args.policy_name
            key_b64 = args.key_b64

        expiry = args.unix_expiry if args.unix_expiry else compute_expiry(args.ttl)
        resource_uri = build_resource_uri(host, device_id, module_id)
        token = build_sas(resource_uri, key_b64, expiry, policy_name)

        print(token)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
