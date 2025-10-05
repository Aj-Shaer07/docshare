#!/usr/bin/env python3
"""
peer_server.py
Wi-Fi (TCP) TLS server with mutual TLS authentication.
Handles resumable, chunked file uploads.
"""

import asyncio, ssl, json, os, hashlib, argparse
from pathlib import Path

CHUNK_SIZE = 1024 * 1024


async def handle_client(reader, writer, storage_dir):
    peer = writer.get_extra_info("peername")
    sslobj = writer.get_extra_info("ssl_object")
    client_cert = sslobj.getpeercert(binary_form=False) if sslobj else None
    print("Incoming connection from", peer, "client_cert_present:", bool(client_cert))

    # Read metadata
    try:
        hdr_len_b = await reader.readexactly(4)
    except asyncio.IncompleteReadError:
        writer.close();
        await writer.wait_closed();
        return
    hdr_len = int.from_bytes(hdr_len_b, "big")
    meta_raw = await reader.readexactly(hdr_len)
    meta = json.loads(meta_raw.decode())

    transfer_id = meta.get("transfer_id") or os.urandom(8).hex()
    filename = os.path.basename(meta["filename"])
    filesize = int(meta["filesize"])
    expected_sha256 = meta.get("file_sha256")

    storage_dir = Path(storage_dir)
    transfer_dir = storage_dir / transfer_id
    transfer_dir.mkdir(parents=True, exist_ok=True)

    temp_path = transfer_dir / (filename + ".part")
    state_path = transfer_dir / "state.json"

    # Load state
    state = json.loads(state_path.read_text()) if state_path.exists() else {"received": 0}

    # Send resume offset
    resp = json.dumps({"resume_offset": state["received"]}).encode()
    writer.write(len(resp).to_bytes(4, "big") + resp)
    await writer.drain()

    # Receive chunks
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
                if hashlib.sha256(data).hexdigest() != sha:
                    nack = json.dumps({"status": "nack", "index": hdr.get("index")}).encode()
                    writer.write(len(nack).to_bytes(4, "big") + nack)
                    await writer.drain()
                    continue
                out_f.write(data);
                out_f.flush()
                state["received"] += len(data)
                state_path.write_text(json.dumps(state))
                ack = json.dumps({"status": "ack", "received": state["received"]}).encode()
                writer.write(len(ack).to_bytes(4, "big") + ack)
                await writer.drain()

            elif t == "finish":
                out_f.flush()
                # Verify checksum
                if expected_sha256:
                    with open(temp_path, "rb") as f:
                        if hashlib.sha256(f.read()).hexdigest() != expected_sha256:
                            fail = json.dumps({"status": "fail", "reason": "checksum_mismatch"}).encode()
                            writer.write(len(fail).to_bytes(4, "big") + fail)
                            await writer.drain()
                            break
                final_path = storage_dir / filename
                os.replace(temp_path, final_path)
                succ = json.dumps({"status": "success", "file": str(final_path)}).encode()
                writer.write(len(succ).to_bytes(4, "big") + succ)
                await writer.drain()
                print("Received file:", final_path)
                break

            else:
                print("Unknown frame type", t)
                break

    writer.close()
    await writer.wait_closed()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="192.168.137.26")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--ca", required=True)
    parser.add_argument("--storage", default="./incoming")
    args = parser.parse_args()

    os.makedirs(args.storage, exist_ok=True)

    sslctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    sslctx.verify_mode = ssl.CERT_REQUIRED
    sslctx.load_cert_chain(certfile=args.cert, keyfile=args.key)
    sslctx.load_verify_locations(cafile=args.ca)

    async def run():
        server = await asyncio.start_server(lambda r, w: handle_client(r, w, args.storage),
                                            host=args.host, port=args.port, ssl=sslctx)
        print("Listening on", args.host, args.port)
        async with server:
            await server.serve_forever()

    asyncio.run(run())


if __name__ == "__main__":
    main()
