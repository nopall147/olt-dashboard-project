"""Small read-only RouterOS API client for PPP monitoring."""
import socket
import ssl


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    if length < 0x4000:
        return bytes([(length >> 8) | 0x80, length & 0xFF])
    if length < 0x200000:
        return bytes([(length >> 16) | 0xC0, (length >> 8) & 0xFF, length & 0xFF])
    if length < 0x10000000:
        return bytes([(length >> 24) | 0xE0, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])
    return b"\xF0" + length.to_bytes(4, "big")


class RouterOSApi:
    def __init__(self, host: str, port: int, username: str, password: str, use_tls: bool = True, timeout: float = 8):
        self.host, self.port = host, port
        self.username, self.password = username, password
        self.use_tls, self.timeout = use_tls, timeout
        self.connection = None

    def connect(self):
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self.connection = ssl.create_default_context().wrap_socket(raw, server_hostname=self.host) if self.use_tls else raw
        self._write_sentence(["/login", f"=name={self.username}", f"=password={self.password}"])
        self._read_sentence_group()
        return self

    def close(self):
        if self.connection:
            self.connection.close()
            self.connection = None

    def _read_exact(self, count: int) -> bytes:
        data = bytearray()
        while len(data) < count:
            chunk = self.connection.recv(count - len(data))
            if not chunk:
                raise ConnectionError("Koneksi MikroTik terputus")
            data.extend(chunk)
        return bytes(data)

    def _read_length(self) -> int:
        first = self._read_exact(1)[0]
        if first < 0x80:
            return first
        if first < 0xC0:
            return ((first & 0x3F) << 8) + self._read_exact(1)[0]
        if first < 0xE0:
            tail = self._read_exact(2)
            return ((first & 0x1F) << 16) + int.from_bytes(tail, "big")
        if first < 0xF0:
            tail = self._read_exact(3)
            return ((first & 0x0F) << 24) + int.from_bytes(tail, "big")
        if first == 0xF0:
            return int.from_bytes(self._read_exact(4), "big")
        raise ValueError("Format panjang data RouterOS tidak dikenal")

    def _write_sentence(self, words):
        payload = bytearray()
        for word in words:
            encoded = word.encode("utf-8")
            payload.extend(_encode_length(len(encoded)))
            payload.extend(encoded)
        payload.append(0)
        self.connection.sendall(payload)

    def _read_sentence(self):
        words = []
        while True:
            length = self._read_length()
            if length == 0:
                return words
            words.append(self._read_exact(length).decode("utf-8", errors="replace"))

    def _read_sentence_group(self):
        rows = []
        while True:
            words = self._read_sentence()
            if not words:
                continue
            kind = words[0]
            if kind == "!re":
                row = {}
                for word in words[1:]:
                    if word.startswith("=") and "=" in word[1:]:
                        key, value = word[1:].split("=", 1)
                        row[key] = value
                rows.append(row)
            elif kind == "!trap":
                message = next((word.split("=", 2)[-1] for word in words if word.startswith("=message=")), "Perintah ditolak")
                raise RuntimeError(message)
            elif kind == "!done":
                return rows

    def query(self, command: str):
        self._write_sentence([command])
        return self._read_sentence_group()

    def ppp_overview(self):
        active = self.query("/ppp/active/print")
        secrets = self.query("/ppp/secret/print")
        return active, secrets
