
#!/usr/bin/env python3
"""
peer_server.py
A TLS server that requires client certificates (mutual TLS). Accepts resumable, chunked uploads.
Usage:
  python peer_server.py --host 0.0.0.0 --port 9000 --cert ./certs/mydevice-cert.pem --key ./certs/mydevice-key.pem --ca ca.pem --storage ./incoming
"""
import asyncio, ssl, json, os, hashlib, argparse
from pathlib import Path

CHUNK_SIZE = 1024*1024

async def handle_client(reader, writer, storage_dir):
    peer = writer.get_extra_info("peername")
    sslobj = writer.get_extra_info("ssl_object")
    client_cert = None
    if sslobj:
        client_cert = sslobj.getpeercert(binary_form=False)
    print("Incoming connection from", peer, "client_cert_present:", bool(client_cert))

    # Read metadata (4-byte len + JSON)
    try:
        hdr_len_b = await reader.readexactly(4)
    except asyncio.IncompleteReadError:
        writer.close(); await writer.wait_closed(); return
    hdr_len = int.from_bytes(hdr_len_b, "big")
    meta_raw = await reader.readexactly(hdr_len)
    meta = json.loads(meta_raw.decode())
    transfer_id = meta.get("transfer_id")
    if not transfer_id:
        transfer_id = os.urandom(8).hex()
    filename = os.path.basename(meta["filename"])
    filesize = int(meta["filesize"])
    expected_sha256 = meta.get("file_sha256")
    storage_dir = Path(storage_dir)
    transfer_dir = storage_dir / transfer_id
    transfer_dir.mkdir(parents=True, exist_ok=True)
    temp_path = transfer_dir / (filename + ".part")
    state_path = transfer_dir / "state.json"

    # load state
    if state_path.exists():
        state = json.loads(state_path.read_text())
    else:
        state = {"received": 0}

    # send resume offset
    resp = json.dumps({"resume_offset": state["received"]}).encode()
    writer.write(len(resp).to_bytes(4, "big") + resp)
    await writer.drain()

    # open file for append
    with open(temp_path, "ab") as out_f:
        out_f.seek(state["received"])
        while True:
            try:
                hdr_len_b = await reader.readexactly(4)
            except asyncio.IncompleteReadError:
                break
            hdr_len = int.from_bytes(hdr_len_b, "big")
            hdr_raw = await reader.readexactly(hdr_len)
            hdr = json.loads(hdr_raw.decode())
            t = hdr.get("type")
            if t == "chunk":
                clen = int(hdr["len"])
                sha = hdr["sha256"]
                data = await reader.readexactly(clen)
                h = hashlib.sha256(data).hexdigest()
                if h != sha:
                    nack = json.dumps({"status":"nack","index":hdr.get("index")}).encode()
                    writer.write(len(nack).to_bytes(4,"big") + nack)
                    await writer.drain()
                    continue
                out_f.write(data); out_f.flush()
                state["received"] += len(data)
                state_path.write_text(json.dumps(state))
                ack = json.dumps({"status":"ack","received":state["received"]}).encode()
                writer.write(len(ack).to_bytes(4,"big") + ack)
                await writer.drain()
            elif t == "finish":
                # verify final SHA if present
                out_f.flush()
                if expected_sha256:
                    with open(temp_path, "rb") as f:
                        full = f.read()
                    final_h = hashlib.sha256(full).hexdigest()
                    if final_h != expected_sha256:
                        fail = json.dumps({"status":"fail","reason":"checksum_mismatch","actual":final_h}).encode()
                        writer.write(len(fail).to_bytes(4,"big") + fail)
                        await writer.drain()
                        break
                # finalize
                final_path = storage_dir / filename
                os.replace(temp_path, final_path)
                succ = json.dumps({"status":"success","file":str(final_path)}).encode()
                writer.write(len(succ).to_bytes(4,"big") + succ)
                await writer.drain()
                print("Received file:", final_path)
                break
            else:
                print("Unknown frame type", t); break

    writer.close()
    await writer.wait_closed()

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="172.20.10.3")
    p.add_argument("--port", type=int, default=9000)
    p.add_argument("--cert", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--ca", required=True)
    p.add_argument("--storage", default="./incoming")
    args = p.parse_args()

    os.makedirs(args.storage, exist_ok=True)

    sslctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    sslctx.verify_mode = ssl.CERT_REQUIRED
    sslctx.load_cert_chain(certfile=args.cert, keyfile=args.key)
    sslctx.load_verify_locations(cafile=args.ca)
    # prefer ECDHE ciphers (left to OpenSSL defaults; system will choose)

    async def run():
        server = await asyncio.start_server(lambda r,w: handle_client(r,w,args.storage),
                                            host=args.host, port=args.port, ssl=sslctx)
        print("Listening on", args.host, args.port)
        async with server:
            await server.serve_forever()
    asyncio.run(run())

if __name__ == "__main__":
    main()

