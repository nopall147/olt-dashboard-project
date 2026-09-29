from pathlib import Path
from netmiko import ConnectHandler
from jinja2 import Template

def deploy_onu_zte(olt_ip, username, password, data_input):
    # 1. Render template Jinja2 menjadi perintah CLI utuh
    template_path = Path(__file__).with_name("zte_omci_wan.j2")
    with template_path.open(encoding="utf-8") as f:
        template = Template(f.read())
    
    commands_text = template.render(**data_input)
    commands_list = [line.strip() for line in commands_text.split('\n') if line.strip()]

    # 2. Detail koneksi Telnet/SSH
    device = {
        'device_type': 'zte_zxros',
        'host': olt_ip,
        'username': username,
        'password': password,
        'port': data_input.get('telnet_port', 23),
    }

    # 3. Kirim komando via Netmiko
    net_connect = None
    try:
        net_connect = ConnectHandler(**device)
        output = net_connect.send_config_set(commands_list)
        if any(token in output.lower() for token in ("% error", "invalid command", "unknown command", "failed")):
            return {"status": "error", "message": output}
        return {"status": "success", "output": output}
    except Exception as e:
        return {"status": "error", "message": str(e)}
    finally:
        if net_connect:
            net_connect.disconnect()
