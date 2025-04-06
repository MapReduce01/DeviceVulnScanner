import ftplib
import socket

def check_ftpaccess(target_ip, port):
    """Check if FTP is open and allows anonymous login."""
    try:
        print(f"[*] Checking if {target_ip}:{port} is open...")
        
        # Test if port 21 is reachable
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)  # Increase timeout
        result = sock.connect_ex((target_ip, port))
        if result != 0:
            print("[!] FTP port is closed or filtered.")
            return False
        sock.close()

        print("[+] FTP port is open. Trying to connect...")

        # Attempt to connect via FTP
        ftp = ftplib.FTP()
        ftp.set_debuglevel(2)  # Enable verbose FTP debugging
        ftp.connect(target_ip, port, timeout=10)

        try:
            ftp.set_pasv(True)  # Try passive mode first
            ftp.login("anonymous", "anonymous@example.com")
            print("[+] Anonymous login successful in PASSIVE mode!")
        except ftplib.error_perm:
            print("[-] Passive mode failed. Trying ACTIVE mode...")
            ftp.set_pasv(False)  # Switch to active mode
            ftp.login("anonymous", "anonymous@example.com")
            print("[+] Anonymous login successful in ACTIVE mode!")

        ftp.quit()
        return True
    except socket.timeout:
        print("[!] Connection timed out. Possible firewall or network issue.")
    except ConnectionRefusedError:
        print("[!] Connection refused. FTP service might be disabled.")
    except ftplib.error_perm as e:
        print(f"[-] Anonymous login denied. FTP response: {e}")
    except Exception as e:
        print(f"[!] Unexpected error: {e}")

    return False

