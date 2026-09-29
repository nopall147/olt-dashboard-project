from netmiko import ConnectHandler
from jinja2 import Template

def deploy_onu_zte(olt_ip, username, password, data_input):
    # 1. Render template Jinja2 menjadi perintah CLI utuh
    with open("app/templates/zte_omci_wan.j2") as f:
        template = Template(f.read())
    
    commands_text = template.render(**data_input)
    commands_list = [line.strip() for line in commands_text.split('\n') if line.strip()]

    # 2. Detail koneksi Telnet/SSH
    device = {
        'device_type': 'zte_zxros',
        'host': olt_ip,
        'username': username,
        'password': password,
        'port': 23, # Gunakan 22 jika pakai SSH
    }

    # 3. Kirim komando via Netmiko
    try:
        net_connect = ConnectHandler(**device)
        output = net_connect.send_config_set(commands_list)
        net_connect.disconnect()
        return {"status": "success", "output": output}
    except Exception as e:
        return {"status": "error", "message": str(e)}