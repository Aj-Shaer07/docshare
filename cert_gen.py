
#!/usr/bin/env python3
"""
cert_gen.py
Generate a local CA (if not present) and create a device certificate signed by that CA.
Outputs:
 - ca.pem         (PEM CA cert)
 - ca-key.pem     (PEM CA key)  [keep secure]
 - <device_id>-cert.pem
 - <device_id>-key.pem
Also prints:
 - cert fingerprint (SHA256 hex)
 - 6-digit SAS code derived for easy human verification

Usage:
  python cert_gen.py --device-id myphone --outdir ./certs

Requirements:
  pip install cryptography
"""
import os
import argparse
import datetime
import ipaddress
import hashlib
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption

def write_pem(path, data: bytes):
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, 0o600)

def create_ca(ca_path, ca_key_path, subject_name="Local Transfer CA"):
    if os.path.exists(ca_path) and os.path.exists(ca_key_path):
        print(f"Found existing CA at {ca_path}")
        return

    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_name)])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    write_pem(ca_key_path, key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))
    write_pem(ca_path, cert.public_bytes(Encoding.PEM))
    print(f"Generated CA cert -> {ca_path}, CA key -> {ca_key_path}")

def create_device_cert(ca_path, ca_key_path, device_id, outdir, ip_addresses=None, dns_names=None):
    # load CA
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(ca_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    # generate device key (ECDSA for smaller keys, good perf)
    key = ec.generate_private_key(ec.SECP384R1())
    now = datetime.datetime.utcnow()
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, device_id)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
    )

    san_list = []
    ip_addresses = ip_addresses or []
    dns_names = dns_names or []
    for ip in ip_addresses:
        san_list.append(x509.IPAddress(ipaddress.ip_address(ip)))
    for d in dns_names:
        san_list.append(x509.DNSName(d))
    if san_list:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_list), critical=False)

    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    os.makedirs(outdir, exist_ok=True)
    cert_path = os.path.join(outdir, f"{device_id}-cert.pem")
    key_path = os.path.join(outdir, f"{device_id}-key.pem")
    write_pem(cert_path, cert.public_bytes(Encoding.PEM))
    write_pem(key_path, key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))

    # fingerprint & SAS
    der = cert.public_bytes(Encoding.DER)
    fp = hashlib.sha256(der).hexdigest()
    sas = f"{int(fp,16) % 1000000:06d}"

    print("Wrote device cert:", cert_path)
    print("Wrote device key: ", key_path)
    print("Cert SHA256 fingerprint:", fp)
    print("SAS code (6 digits):", sas)
    return cert_path, key_path, fp, sas

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--device-id", required=True)
    p.add_argument("--outdir", default="./certs")
    p.add_argument("--ca-cert", default="ca.pem")
    p.add_argument("--ca-key", default="ca-key.pem")
    p.add_argument("--ip", action="append", help="Add IP to SAN (can appear multiple times)")
    p.add_argument("--dns", action="append", help="Add DNS name to SAN (optional)")
    args = p.parse_args()

    create_ca(args.ca_cert, args.ca_key)
    create_device_cert(args.ca_cert, args.ca_key, args.device_id, args.outdir, ip_addresses=args.ip, dns_names=args.dns)

if __name__ == "__main__":
    main()

