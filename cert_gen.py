#!/usr/bin/env python3
"""
cert_gen.py
Generates CA, device certificates, and private keys for mutual TLS communication.
Usage:
  python cert_gen.py --device-id deviceA --outdir ./certsA --ip 172.20.10.3
  python cert_gen.py --device-id deviceB --outdir ./certsB --ip 172.20.10.3
"""
import os, subprocess, argparse

def run(cmd):
    print(">", " ".join(cmd))
    subprocess.run(cmd, check=True)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--device-id", required=True)
    p.add_argument("--outdir", required=True)
    p.add_argument("--ip", required=True)
    args = p.parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    ca_cert = f"{args.outdir}/ca.pem"
    ca_key = f"{args.outdir}/ca-key.pem"

    if not os.path.exists(ca_cert):
        print("🔐 Generating CA certificate...")
        run(["openssl", "req", "-x509", "-newkey", "rsa:4096", "-sha256",
             "-days", "365", "-nodes",
             "-subj", "/CN=PeerShare-CA",
             "-keyout", ca_key, "-out", ca_cert])

    print(f"📜 Generating cert for {args.device_id}")
    key = f"{args.outdir}/{args.device_id}-key.pem"
    csr = f"{args.outdir}/{args.device_id}.csr"
    cert = f"{args.outdir}/{args.device_id}-cert.pem"
    conf = f"{args.outdir}/ext.cnf"

    with open(conf, "w") as f:
        f.write(f"subjectAltName = IP:{args.ip}\n")

    run(["openssl", "req", "-newkey", "rsa:2048", "-nodes",
         "-keyout", key, "-out", csr, "-subj", f"/CN={args.device_id}"])
    run(["openssl", "x509", "-req", "-in", csr, "-CA", ca_cert, "-CAkey", ca_key,
         "-CAcreateserial", "-out", cert, "-days", "365", "-sha256",
         "-extfile", conf])

if __name__ == "__main__":
    main()
