#!/usr/bin/env python3
"""
mdns_advertiser.py
Announce a small service record via mDNS / Zeroconf. This works across Linux/macOS/Windows.

Flow:
  - The TXT record contains a compact JSON (ip,port,device_id,sas,fingerprint)
  - Peers can discover service instances and connect to the advertised IP:port

Usage:
  python mdns_advertiser.py --device-id "MyPhone" --port 9000 --sas 123456 --fingerprint <hex>

Requirements:
  pip install zeroconf
"""
import argparse
import json
import socket
from zeroconf import ServiceInfo, Zeroconf

def main():
    # Parse command line arguments
    p = argparse.ArgumentParser()
    p.add_argument("--device-id", required=True, help="Unique device identifier")
    p.add_argument("--port", type=int, required=True, help="Port to advertise")
    p.add_argument("--sas", required=True, help="6-digit SAS code for human verification")
    p.add_argument("--fingerprint", required=True, help="SHA256 fingerprint of the device certificate")
    args = p.parse_args()

    # Build payload for mDNS TXT record
    hostname = socket.gethostname() + ".local."
    ip = socket.gethostbyname(socket.gethostname())  # IP of this host
    payload = {
        "ip": ip,
        "port": args.port,
        "device": args.device_id,
        "sas": args.sas,
        "fp": args.fingerprint
    }

    txt = json.dumps(payload).encode()
    desc = {"info": txt.decode()}  # JSON encoded into TXT record

    # Create Zeroconf service info
    info = ServiceInfo(
        type_="_p2ptransfer._tcp.local.",
        name=f"{args.device_id}._p2ptransfer._tcp.local.",
        addresses=[socket.inet_aton(ip)],
        port=args.port,
        properties=desc,
        server=hostname
    )

    zc = Zeroconf()
    try:
        zc.register_service(info)
        print("Registered mDNS service for", args.device_id)
        print("TXT payload:", payload)
        print("Press Ctrl-C to exit and unregister")
        import time
        while True:
            time.sleep(1)  # Keep the service running
    except KeyboardInterrupt:
        print("Unregistering mDNS service")
    finally:
        zc.unregister_service(info)
        zc.close()

if __name__ == "__main__":
    main()
