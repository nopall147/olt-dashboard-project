import os
import re
from typing import List, Dict, Any
from app.services.netmiko_driver import open_telnet

def is_mock_active() -> bool:
    """Cek apakah mode mock aktif baik dari MOCK_OLT maupun USE_MOCK_DATA."""
    mock_env = os.getenv("MOCK_OLT") or os.getenv("USE_MOCK_DATA") or "false"
    return mock_env.lower() in ("true", "1", "yes")

def fetch_onu_realtime(olt_config) -> List[Dict[str, Any]]:
    """
    Mengambil data telemetri real-time dari ZTE OLT.
    Jika mode mock aktif, kembalikan data simulasi.
    Jika tidak, hubungi perangkat via Telnet Netmiko secara aman.
    """
    if is_mock_active():
        return [
            {
                "gpon_port": "1/1/1:1",
                "sn_mac": "ZTEG12345678",
                "status": "working",
                "rx_onu": -19.45,
                "rx_olt": -20.12,
                "customer_name": "Demo Pelanggan 1",
                "description": "Simulated ONU"
            }
        ]
    
    # Mode Produksi: Eksekusi CLI ZTE C300/C320
    results = []
    conn = None
    try:
        conn = open_telnet(olt_config)
        output = conn.send_command("show gpon onu state", read_timeout=15)
        
        # Parsing output tabel 'show gpon onu state'
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("OnuIndex") or line.startswith("---"):
                continue
            parts = line.split()
            if len(parts) >= 4:
                gpon_port = parts[0]
                status_state = parts[3].lower()
                
                results.append({
                    "gpon_port": gpon_port,
                    "status": status_state,
                    "sn_mac": parts[1] if len(parts) > 1 else "N/A"
                })
    except Exception as e:
        print(f"[ERROR] Gagal membaca telemetri OLT {getattr(olt_config, 'name', 'Unknown')}: {e}")
    finally:
        # SELALU tutup sesi telnet agar slot VTY di OLT tidak menggantung/penuh
        if conn:
            try:
                conn.disconnect()
            except Exception:
                pass
        
    return results