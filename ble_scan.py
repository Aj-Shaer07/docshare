
#!/usr/bin/env python3
"""
ble_scan.py
Scan for BLE advertisements and print manufacturer data / service data.
Helpful to find mobile advertisers that broadcast a small JSON token.
Requires: pip install bleak

Note: Advertising from Python is platform-dependent and often restricted on macOS/Windows without native APIs.
For mobile apps implement native BLE advertisement (Android/iOS) which can broadcast the JSON token; use this scanner to discover.
"""
import asyncio
from bleak import BleakScanner
import json

async def run(timeout=5.0):
    print("Scanning for BLE devices...")
    devices = await BleakScanner.discover(timeout=timeout)
    for d in devices:
        print("----")
        print("Name:", d.name, "Address:", d.address)
        # platform-dependent advertisement data:
        print("Details:", d.details)
        # manufacturer data:
        m = d.metadata.get("manufacturer_data", {})
        if m:
            print("Manufacturer data:", m)
        sd = d.metadata.get("service_data", {})
        if sd:
            print("Service data:", sd)
        # some advertisers embed JSON in Tx power or local name; try to parse local name if JSON-like
        try:
            if d.name and (d.name.strip().startswith("{") or d.name.strip().startswith("[")):
                print("Local-name JSON:", json.loads(d.name))
        except Exception:
            pass

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--timeout", type=float, default=5.0)
    args = p.parse_args()
    asyncio.run(run(timeout=args.timeout))

