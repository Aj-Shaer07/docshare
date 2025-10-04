#!/usr/bin/env python3
"""
uploader.py
Send a file to a discovered peer using mutual TLS. The peer must present a cert signed by the same CA.
Usage:
  python uploader.py host port --cert ./certs/mydevice-cert.pem --key ./certs/mydevice-key.pem --ca ca.pem
"""
import asyncio, ssl, json, os, argparse, hashlib, uuid
import nest_asyncio

CHUNK_SIZE = 1024 * 1024

# Allow reusing event loop in PyCharm / interactive environments
nest_asyncio.apply()


async def send_file(host, port, filepath, cert, key, ca):
    sslctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
    sslctx.load_cert_chain(certfile=cert, keyfile=key)
    reader, writer = await asyncio.open_connection(host=host, port=port, ssl=sslctx)

    filesize = os.path.getsize(filepath)
    filename = os.path.basename(filepath)
    transfer_id = str(uuid.uuid4())

    # Compute full SHA256
    print("Computing SHA256...")
    hobj = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            d = f.read(CHUNK_SIZE)
            if not d:
                break
            hobj.update(d)
    file_sha = hobj.hexdigest()

    meta = {"filename": filename, "filesize": filesize, "chunk_size": CHUNK_SIZE, "file_sha256": file_sha,
            "transfer_id": transfer_id}
    mbytes = json.dumps(meta).encode()
    writer.write(len(mbytes).to_bytes(4, "big") + mbytes)
    await writer.drain()

    # Read resume offset
    hdr_len_b = await reader.readexactly(4)
    hdr_len = int.from_bytes(hdr_len_b, "big")
    hdr_raw = await reader.readexactly(hdr_len)
    info = json.loads(hdr_raw.decode())
    offset = info.get("resume_offset", 0)
    print("Server resume_offset:", offset)

    idx = offset // CHUNK_SIZE
    with open(filepath, "rb") as f:
        f.seek(offset)
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            clen = len(chunk)
            chk = hashlib.sha256(chunk).hexdigest()
            hdr = {"type": "chunk", "index": idx, "len": clen, "sha256": chk}
            hdr_b = json.dumps(hdr).encode()
            writer.write(len(hdr_b).to_bytes(4, "big") + hdr_b)
            writer.write(chunk)
            await writer.drain()

            # Read ack
            ack_len_b = await reader.readexactly(4)
            ack_len = int.from_bytes(ack_len_b, "big")
            ack_raw = await reader.readexactly(ack_len)
            ack = json.loads(ack_raw.decode())
            if ack.get("status") == "ack":
                idx += 1
                print(f"Sent chunk {idx}, server received {ack.get('received')}")
            else:
                print("NACK -> resending chunk")
                f.seek(-clen, os.SEEK_CUR)

    # Finish
    fin = {"type": "finish"}
    fb = json.dumps(fin).encode()
    writer.write(len(fb).to_bytes(4, "big") + fb)
    await writer.drain()

    try:
        final_len_b = await reader.readexactly(4)
        final_len = int.from_bytes(final_len_b, "big")
        final_raw = await reader.readexactly(final_len)
        print("Server final:", json.loads(final_raw.decode()))
    except asyncio.IncompleteReadError:
        print("No final response")

    writer.close()
    await writer.wait_closed()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("host")
    p.add_argument("port", type=int)
    p.add_argument("--cert", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--ca", required=True)
    args = p.parse_args()

    # Ask user for file path until a valid file is provided
    while True:
        filepath = input("Enter the path of the file to upload: ").strip()
        if os.path.isfile(filepath):
            break
        print(f"Error: File '{filepath}' does not exist. Please try again.")

    # Use existing event loop
    loop = asyncio.get_event_loop()
    loop.run_until_complete(send_file(args.host, args.port, filepath, args.cert, args.key, args.ca))


if __name__ == "__main__":
    main()
