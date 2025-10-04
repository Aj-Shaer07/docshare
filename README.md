
---

# DocShare: Secure Multi-Server File Transfer with mTLS

## Overview

**DocShare** is a Python-based secure file transfer system that allows multiple devices and servers to send files to each other over a local network.

Key features:

* **Mutual TLS (mTLS)** authentication for both client and server.
* **Resumable, chunked file uploads** with SHA256 verification.
* **mDNS / Zeroconf discovery** of peers.
* Support for **multiple servers**, allowing devices to select which servers to upload to.

---

## Why Signed Certificates Are Needed

1. **Mutual TLS Authentication:**
   Both the uploader (client) and server verify each other's identity.

2. **Server Verification:**
   Ensures the uploader only connects to servers signed by the trusted CA.

3. **Client Verification:**
   Ensures that only authorized clients can upload files to servers.

4. **Encrypted Communication:**
   All data is encrypted, preventing eavesdropping or tampering.

5. **Trust via Common CA:**
   A single CA (`ca.pem`) signs all device certificates, establishing trust across all peers.

---

## Requirements for Sending Files

1. **Valid Certificates:**

   * Each device/server needs:

     * Device certificate (e.g., `deviceA-cert.pem`)
     * Device private key (e.g., `deviceA-key.pem`)
   * Certificates must be signed by the same CA (`ca.pem`).

2. **Correct Run Configurations:**

   * Provide the paths to the certificate, key, and CA for each uploader/server.

3. **Reachable IP & Port:**

   * Server must be accessible on the specified IP and port.
   * Certificates should include the server IP in SAN if verification is strict.

4. **File Path:**

   * Ensure the file exists before uploading.

5. **Network Accessibility:**

   * Devices and servers should be on the same subnet for mDNS discovery.

---

## Folder Structure

```
docshare/
│
├── peer_server.py
├── uploader.py
├── mdns_advertiser.py
├── certsA/
│   ├── deviceA-cert.pem
│   ├── deviceA-key.pem
│   └── ca.pem
└── certsB/
    ├── deviceB-cert.pem
    ├── deviceB-key.pem
    └── ca.pem
```

---

## Step-by-Step Setup

### 1. Install Dependencies

```bash
pip install cryptography zeroconf nest_asyncio
```

---

### 2. Generate CA and Device Certificates

#### Generate CA (if not already present):

```bash
python cert_gen.py --device-id myCA --outdir ./certs
```

#### Generate Device Certificates:

For **Device A**:

```bash
python cert_gen.py --device-id deviceA --outdir ./certsA --ca-cert ./certsA/ca.pem --ca-key ./certsA/ca-key.pem --ip 172.20.10.3
```

For **Device B**:

```bash
python cert_gen.py --device-id deviceB --outdir ./certsB --ca-cert ./certsB/ca.pem --ca-key ./certsB/ca-key.pem --ip 172.20.10.3
```

> ⚠ Ensure **both devices share the same CA** for mutual trust.

---

### 3. Run Peer Servers

#### Server A:

```bash
python peer_server.py --host 172.20.10.3 --port 9000 --cert ./certsA/deviceA-cert.pem --key ./certsA/deviceA-key.pem --ca ./certsA/ca.pem --storage ./incomingA
```

#### Server B:

```bash
python peer_server.py --host 172.20.10.3 --port 9001 --cert ./certsB/deviceB-cert.pem --key ./certsB/deviceB-key.pem --ca ./certsB/ca.pem --storage ./incomingB
```

> Use separate ports for each server.

---

### 4. Advertise Servers via mDNS

#### Server A:

```bash
python mdns_advertiser.py --name "ServerA" --port 9000 --sas 123456 --fingerprint <deviceA-cert-fingerprint>
```

#### Server B:

```bash
python mdns_advertiser.py --name "ServerB" --port 9001 --sas 654321 --fingerprint <deviceB-cert-fingerprint>
```

---

### 5. Run Uploaders

Uploader prompts for the file path interactively:

#### Uploader from Device A to Server B:

```bash
python uploader.py 172.20.10.3 9001 --cert ./certsA/deviceA-cert.pem --key ./certsA/deviceA-key.pem --ca ./certsA/ca.pem
```

#### Uploader from Device B to Server A:

```bash
python uploader.py 172.20.10.3 9000 --cert ./certsB/deviceB-cert.pem --key ./certsB/deviceB-key.pem --ca ./certsB/ca.pem
```

---

### 6. Sending Files to Selected Servers

* After entering the uploader, you can choose which server to send the file to.
* mDNS allows discovery of available servers.
* Only servers whose certificates are signed by the **trusted CA** will accept uploads.

---

## Adding More Servers

1. Generate a new device certificate signed by the **same CA**.
2. Run the peer server on a **unique port**.
3. Advertise via mDNS.
4. Use uploader to connect to the new server using the correct certificate and CA.

---

## Architecture Diagram

```text
                   +------------------+
                   |   Device A       |
                   |  Uploader A      |
                   |  Cert: deviceA   |
                   |  Key: deviceA    |
                   +--------+---------+
                            |
             TLS/mTLS Verify|
             Cert signed by |
             common CA      |
                            v
                 +----------+----------+
                 |     Server B        |
                 |  Peer Server        |
                 |  Cert: deviceB      |
                 |  Key: deviceB       |
                 |  CA: common CA      |
                 +----------+----------+
                            ^
             TLS/mTLS Verify|
             Cert signed by |
             common CA      |
                            |
                   +--------+---------+
                   |   Device B       |
                   |  Uploader B      |
                   |  Cert: deviceB   |
                   |  Key: deviceB    |
                   +------------------+

Other servers (C, D, ...) can be added in the same way.

Legend:
- All arrows represent TLS-encrypted connections.
- mTLS ensures both client and server verify each other.
- Common CA allows trust between all devices/servers.
```

---

### Notes

* Always use **unique ports** for each server.
* Ensure all certificates include the correct **IP/DNS** in the SAN field.
* File uploads are **resumable** and verified using SHA256.
* Certificates signed by a **different CA** or missing SAN entries will fail verification.


