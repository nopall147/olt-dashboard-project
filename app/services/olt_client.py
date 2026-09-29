import os
import re

from netmiko import ConnectHandler

from app.services.snmp_client import get_value


def env_key(olt_name):
    key = re.sub(r"[^A-Z0-9]+", "_", olt_name.upper()).strip("_")
    return key[4:] if key.startswith("OLT_") else key


def snmp_community(olt_name):
    return os.getenv(f"OLT_{env_key(olt_name)}_SNMP_COMMUNITY", "")


def telnet_password(olt_name):
    return os.getenv(f"OLT_{env_key(olt_name)}_TELNET_PASSWORD", "")


def test_snmp(olt):
    community = snmp_community(olt.name)
    if not community:
        raise RuntimeError(f"Set OLT_{env_key(olt.name)}_SNMP_COMMUNITY di environment")
    return {
        "description": get_value(olt.ip_address, olt.snmp_port, community, "1.3.6.1.2.1.1.1.0"),
        "uptime_ticks": get_value(olt.ip_address, olt.snmp_port, community, "1.3.6.1.2.1.1.3.0"),
    }


def open_telnet(olt):
    password = telnet_password(olt.name)
    if not password:
        raise RuntimeError(f"Set OLT_{env_key(olt.name)}_TELNET_PASSWORD di environment")
    return ConnectHandler(device_type="zte_zxros", host=olt.ip_address,
                          username=olt.telnet_username, password=password,
                          port=olt.telnet_port, conn_timeout=5, banner_timeout=8,
                          auth_timeout=8, fast_cli=False)


def test_telnet(olt):
    connection = open_telnet(olt)
    try:
        return connection.find_prompt()
    finally:
        connection.disconnect()


def read_pon_state(olt, interface):
    connection = open_telnet(olt)
    try:
        return connection.send_command(f"show gpon onu state gpon-olt_{interface}", read_timeout=15)
    finally:
        connection.disconnect()


def read_pon_snapshot(olt, interfaces, onu_ports):
    connection = open_telnet(olt)
    try:
        states = {interface: connection.send_command(f"show gpon onu state gpon-olt_{interface}", read_timeout=15) for interface in interfaces}
        powers = {port: connection.send_command(f"show pon power attenuation gpon-onu_{port}", read_timeout=10) for port in onu_ports}
        return states, powers
    finally:
        connection.disconnect()


def read_onu_traffic(olt, interface):
    connection = open_telnet(olt)
    try:
        return connection.send_command(f"show interface gpon-onu_{interface}", read_timeout=15)
    finally:
        connection.disconnect()
