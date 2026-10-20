import os
import re
from pathlib import Path
from netmiko import ConnectHandler
from jinja2 import Template

def is_mock_active() -> bool:
    """Cek apakah mode simulasi aktif."""
    mock_env = os.getenv("MOCK_OLT") or os.getenv("USE_MOCK_DATA") or "false"
    return mock_env.lower() in ("true", "1", "yes")

def get_telnet_password(olt) -> str:
    """Ambil password dari database jika ada, jika tidak ambil dari .env."""
    if getattr(olt, "telnet_password", None):
        return olt.telnet_password
    safe_name = re.sub(r"[^A-Za-z0-9]", "_", getattr(olt, "name", "")).upper()
    return os.getenv(f"{safe_name}_TELNET_PASSWORD", "")

def open_telnet(olt_config):
    """
    Helper untuk membuka koneksi Telnet ke ZTE OLT.
    Digunakan oleh poller dan fetcher.
    """
    password = get_telnet_password(olt_config)
    device = {
        'device_type': 'zte_zxros_telnet',
        'host': olt_config.ip_address,
        'username': olt_config.telnet_username,
        'password': password,
        'port': getattr(olt_config, 'telnet_port', 23) or 23,
        'conn_timeout': 15,
        'banner_timeout': 15,
        'auth_timeout': 15,
        'fast_cli': False,
    }
    net_connect = ConnectHandler(**device)
    net_connect.enable()
    return net_connect

def deploy_onu_zte(olt_ip, username, password, data_input):
    # Cek mode mock: jika aktif, jangan hubungi OLT fisik
    if is_mock_active():
        return {
            "status": "success",
            "output": f"[MOCK] Berhasil simulasi registrasi ONU {data_input.get('sn', 'ZTEG00000000')} ke OLT {olt_ip}"
        }

    # 1. Render template Jinja2 menjadi perintah CLI utuh
    template_path = Path(__file__).with_name("zte_omci_wan.j2")
    with template_path.open(encoding="utf-8") as f:
        template = Template(f.read())
    
    commands_text = template.render(**data_input)
    commands_list = [line.strip() for line in commands_text.split('\n') if line.strip()]

    # 2. Detail koneksi Telnet
    device = {
        'device_type': 'zte_zxros_telnet',
        'host': olt_ip,
        'username': username,
        'password': password,
        'port': data_input.get('telnet_port', 23),
        'conn_timeout': 15,
        'banner_timeout': 15,
        'auth_timeout': 15,
        'fast_cli': False,
    }

    # 3. Kirim komando via Netmiko
    net_connect = None
    try:
        net_connect = ConnectHandler(**device)
        output = net_connect.send_config_set(
            commands_list,
            read_timeout=30,
            cmd_verify=False
        )
        if any(token in output.lower() for token in ("% error", "invalid command", "unknown command", "failed", "failure", "incomplete command")):
            return {"status": "error", "message": output}
        return {"status": "success", "output": output}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        if net_connect:
            net_connect.disconnect()