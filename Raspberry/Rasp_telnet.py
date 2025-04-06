import telnetlib
import time

def telnet_connect(ip, port=23, timeout=10):
    try:
        print(f"Testing ... Connecting to {ip}:{port}...")
        tn = telnetlib.Telnet(ip, port, timeout)
        print(f"Telnet port open ... Easy to be sniffed")
        return True
    except Exception as e:
        print(f"Connection failed: {e}")
        return None
