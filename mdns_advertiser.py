
#!/usr/bin/env python3
"""
mdns_advertiser.py
Announce a small service record via mDNS / Zeroconf. This works across Linux/macOS/Windows.
Flow:
  - The TXT record contains a compact JSON (ip,port,device_id,sas,fingerprint)
  - Peers can discover service instances and connect to the advertised IP:port

Usage:
  python mdns_advertiser.py --name "MyPhone" --port 9000 --sas 123456 --fingerprint <hex>
Requirements:
  pip install zeroconf
"""
import argparse, json, socket
from zeroconf import ServiceInfo, Zeroconf

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--name", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--sas", required=True)
    p.add_argument("--fingerprint", required=True)
    args = p.parse_args()

    # build payload
    hostname = socket.gethostname() + ".local."
    ip = socket.gethostbyname(socket.gethostname())
    payload = {"ip": ip, "port": args.port, "device": args.name, "sas": args.sas, "fp": args.fingerprint}
    txt = json.dumps(payload).encode()

    desc = {"info": txt.decode()}  # small JSON in TXT

    info = ServiceInfo(
        type_="_p2ptransfer._tcp.local.",
        name=f"{args.name}._p2ptransfer._tcp.local.",
        addresses=[socket.inet_aton(ip)],
        port=args.port,
        properties=desc,
        server=hostname
    )
    zc = Zeroconf()
    try:
        zc.register_service(info)
        print("Registered mDNS service for", args.name)
        print("TXT payload:", payload)
        print("Press Ctrl-C to exit and unregister")
        import time
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Unregistering")
    finally:
        zc.unregister_service(info)
        zc.close()

if __name__ == "__main__":
    main()

