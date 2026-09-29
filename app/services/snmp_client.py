"""Small SNMPv2c GET client for basic system identity checks."""
import socket


def _length(size):
    if size < 128:
        return bytes([size])
    raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag, value):
    return bytes([tag]) + _length(len(value)) + value


def _integer(value):
    raw = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big", signed=True)
    if value >= 0 and raw[0] & 0x80:
        raw = b"\x00" + raw
    return _tlv(0x02, raw)


def _oid(value):
    parts = [int(part) for part in value.split(".")]
    encoded = bytearray([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        chunk = [part & 0x7f]
        part >>= 7
        while part:
            chunk.insert(0, 0x80 | (part & 0x7f))
            part >>= 7
        encoded.extend(chunk)
    return _tlv(0x06, bytes(encoded))


def _read_tlv(data, offset=0):
    tag = data[offset]
    first = data[offset + 1]
    if first & 0x80:
        count = first & 0x7f
        size = int.from_bytes(data[offset + 2:offset + 2 + count], "big")
        start = offset + 2 + count
    else:
        size = first
        start = offset + 2
    return tag, data[start:start + size], start + size


def get_value(host, port, community, oid, timeout=3):
    request_id = 1
    varbind = _tlv(0x30, _oid(oid) + _tlv(0x05, b""))
    varbinds = _tlv(0x30, varbind)
    pdu = _tlv(0xa0, _integer(request_id) + _integer(0) + _integer(0) + varbinds)
    packet = _tlv(0x30, _integer(1) + _tlv(0x04, community.encode()) + pdu)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (host, port))
        data, _ = sock.recvfrom(65535)
    _, outer, _ = _read_tlv(data)
    _, _, offset = _read_tlv(outer)
    _, _, offset = _read_tlv(outer, offset)
    _, response_pdu, _ = _read_tlv(outer, offset)
    _, _, pdu_offset = _read_tlv(response_pdu)
    _, error_status, pdu_offset = _read_tlv(response_pdu, pdu_offset)
    if int.from_bytes(error_status, "big") != 0:
        raise RuntimeError("SNMP agent returned an error")
    _, _, pdu_offset = _read_tlv(response_pdu, pdu_offset)
    _, varbind_list, _ = _read_tlv(response_pdu, pdu_offset)
    _, varbind_value, _ = _read_tlv(varbind_list)
    _, _, value_offset = _read_tlv(varbind_value)
    value_tag, value, _ = _read_tlv(varbind_value, value_offset)
    if value_tag == 0x04:
        return value.decode(errors="replace")
    return int.from_bytes(value, "big") if value else None
