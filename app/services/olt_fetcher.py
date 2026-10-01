import random

# Saklar simulasi: True jika coding offline/di rumah, False jika terhubung ke OLT fisik
USE_MOCK_DATA = True 

def fetch_onu_realtime(olt_ip, slot, port, onu_id):
    if USE_MOCK_DATA:
        # Simulasi data seolah-olah ditarik dari OLT ZTE
        return {
            "olt_name": "OLT-C320-Lokal-Lab",
            "slot": slot,
            "port": port,
            "onu_id": onu_id,
            "status": random.choice(["Online", "Online", "LOS", "DyingGasp"]),
            "rx_power": f"-{random.uniform(18.5, 24.5):.2f} dBm",
            "veip_status": "UP"
        }
    else:
        # Kode Netmiko/SNMP asli ke OLT fisik...
        pass