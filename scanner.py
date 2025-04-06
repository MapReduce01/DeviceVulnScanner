import scapy.all as scapy
import nmap
import socket
from Raspberry.Rasp_sshBruteForce import ssh_brute_force
from Raspberry.Rasp_ftpcon import check_ftpcon
from Raspberry.Rasp_ftpaccess import check_ftpaccess
from Raspberry.Rasp_telnet import telnet_connect
from Raspberry.Rasp_sql import test_sql_injection
from Raspberry.Rasp_xss import test_xss
import requests

password_list = open("rockyou.txt", "r", encoding="latin-1").readlines()  # Use a wordlist

def get_local_ip():
    """Get the local machine's IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
    return local_ip

def scan_network(ip_range):
    """Scan the network for connected devices."""
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments="-sn")  # Ping scan

    devices = []
    for host in nm.all_hosts():
        if "mac" in nm[host]["addresses"]:
            mac = nm[host]["addresses"]["mac"]
        else:
            mac = "Unknown"
        devices.append({"ip": host, "mac": mac})
    
    return devices

def nmap_scan(target_ip):
    """Use Nmap to scan for OS, open ports, and possible vulnerabilities."""
    nm = nmap.PortScanner()
    nm.scan(target_ip, arguments="-O -sV")

    scan_results = {"ip": target_ip, "os": "Unknown", "ports": []}
    
    # Detect OS
    if 'osmatch' in nm[target_ip]:
        os_matches = nm[target_ip]['osmatch']
        if os_matches:
            scan_results["os"] = os_matches[0]['name']

    # Detect open ports
    for proto in nm[target_ip].all_protocols():
        for port in nm[target_ip][proto]:
            port_info = {
                "port": port,
                "state": nm[target_ip][proto][port]["state"],
                "service": nm[target_ip][proto][port]["name"]
            }
            scan_results["ports"].append(port_info)
    
    return scan_results

def suggest_vulnerabilities(os, ports):
    """Suggest vulnerabilities based on OS and open ports."""
    vulnerabilities = []

    # OS-based vulnerabilities
    #if "Windows" in os:
        #vulnerabilities.append("⚠️ SMB (EternalBlue) - Ensure SMBv1 is disabled.")
    #elif "Linux" in os:
        #vulnerabilities.append("⚠️ SSH Bruteforce - Weak passwords can be exploited.")
    #elif "Mac OS" in os:
        #vulnerabilities.append("⚠️ Remote exploits via outdated services like AFP.")

    # Port-based vulnerabilities
    for port in ports:
        if port["port"] == 21:
            vulnerabilities.append("⚠️ FTP Port Open - Unencrypted, can be sniffed (use SFTP instead).")
            vulnerabilities.append("⚠️ FTP Access - Check for anonymous access and weak credentials.")
        if port["port"] == 22:
            vulnerabilities.append("⚠️ SSH Bruteforce - Weak passwords can be exploited.")
        if port["port"] == 23:
            vulnerabilities.append("⚠️ Telnet Port Open - Unencrypted protocol, easy to sniff.")
        if port["port"] == 80:
            vulnerabilities.append("⚠️ Web Server (HTTP) SQLi - Could be vulnerable to SQL Injection.")
            vulnerabilities.append("⚠️ Web Server (HTTP) XSS - Could be vulnerable to XSS Injection.")
        

    return vulnerabilities

def scan_and_report():
    local_ip = get_local_ip()
    network_prefix = ".".join(local_ip.split(".")[:3]) + ".1/24"

    print(f"Scanning network: {network_prefix}")
    devices = scan_network(network_prefix)

    # Exclude Kali's own IP
    devices = [device for device in devices if device['ip'] != local_ip]

    print("\nDetected Devices:")
    for device in devices:
        print(f"IP: {device['ip']}  |  MAC: {device['mac']}")

    print("\nRunning Nmap scan...")
    scanned_devices = []
    for device in devices:
        scan_results = nmap_scan(device['ip'])
        scanned_devices.append(scan_results)
        print(f"\nDevice: {scan_results['ip']}")
        print(f"OS: {scan_results['os']}")
        print("Open Ports:")
        for port in scan_results["ports"]:
            print(f"  - {port['port']} ({port['service']}) - {port['state']}")

    while True:

        # Ask user which device to analyze for vulnerabilities
        selected_ip = input("\nWhich device do you want to analyze? Enter the IP address: ")

        ip_params = {
            "ip": selected_ip
        }
        newly_scanned = {"ip":selected_ip,"OS":scan_results['os'], 
            "vuln_FTPPortOpen" : "Not Validated yet",
            "vuln_FTPAccess" : "Not Validated yet",
            "vuln_SSHBruteforce" : "Not Validated yet",
            "vuln_TelnetPortOpen": "Not Validated yet",
            "vuln_WebServerHTTPSQLi": "Not Validated yet",
            "vuln_WebServerHTTPXSS": "Not Validated yet" }
        res = requests.get("http://0.0.0.0:5000/listDeviceInfo", params=ip_params)

        if "200" in str(res):
            print(f"Device existed in DB.")  
            print("Previously Scanned Result: " + "\n")
            print(res.json()) 
        else:
            response = requests.post("http://0.0.0.0:5000/addNewDevice", json=newly_scanned)

        # Find the selected device in the scanned list
        selected_device = next((d for d in scanned_devices if d["ip"] == selected_ip), None)
        res = requests.get("http://0.0.0.0:5000/listDeviceInfo", params=ip_params)

        if selected_device:
            print(f"\nAnalyzing vulnerabilities for {selected_device['ip']} ({selected_device['os']})...")
            vulnerabilities = suggest_vulnerabilities(selected_device["os"], selected_device["ports"])
            
            if vulnerabilities:
                print("\n🔍 Potential Vulnerabilities:")
                for vuln in vulnerabilities:
                    print(f"  - {vuln}")

                autoValidate = input("\nDo you want this program to automatically validate all the potential vulns for you and store them in the DB (Y/N): ")
                if autoValidate == "Y" or autoValidate == "y":   
                    for vuln in vulnerabilities:
                        if  "SSH Bruteforce" in vuln and "Linux" in scan_results['os']:
                            outcome = ssh_brute_force(selected_ip, "user", password_list)
                            if outcome:
                                outcome_str = "True"
                            else:
                                outcome_str = "False"
                            print(f"Updating data entry...")  
                            # The data you want to send in the PUT request
                            data = {
                                "ip": selected_ip,        # The IP address of the device you want to update
                                "update_field": "vuln_SSHBruteforce",        # The field you want to update (e.g., 'OS')
                                "new_value": outcome_str       # The new value to assign to that field
                            }

                            # Sending the PUT request to the FastAPI server
                            response = requests.put("http://0.0.0.0:5000/updateDevice", json=data)
                            print("Database has been updated.")


                        elif  "FTP Port Open" in vuln and "Linux" in scan_results['os']:
                            outcome = check_ftpcon(selected_ip, 21)
                            if outcome:
                                ftpcon = "True"
                            else:
                                ftpcon = "False"

                            print(f"Updating data entry...")  
                            # The data you want to send in the PUT request
                            data = {
                                "ip": selected_ip,        # The IP address of the device you want to update
                                "update_field": "vuln_FTPPortOpen",        # The field you want to update (e.g., 'OS')
                                "new_value": ftpcon       # The new value to assign to that field
                            }

                            # Sending the PUT request to the FastAPI server
                            response = requests.put("http://0.0.0.0:5000/updateDevice", json=data)
                            print("Database has been updated.")
                        

                        elif  "FTP Access" in vuln and "Linux" in scan_results['os']:
                            outcome = check_ftpaccess(selected_ip, 21)
                            if outcome:
                                ftpaccess = "True"
                            else:
                                ftpaccess = "False"
                            if "200" in str(res):
                                print(f"Updating data entry...")  
                                # The data you want to send in the PUT request
                                data = {
                                    "ip": selected_ip,        # The IP address of the device you want to update
                                    "update_field": "vuln_FTPAccess",        # The field you want to update (e.g., 'OS')
                                    "new_value": ftpaccess       # The new value to assign to that field
                                }

                                # Sending the PUT request to the FastAPI server
                                response = requests.put("http://0.0.0.0:5000/updateDevice", json=data)
                                print("Database has been updated.")

                        
                        elif  "Telnet Port Open" in vuln and "Linux" in scan_results['os']:
                            outcome = telnet_connect(ip=selected_ip)
                            if outcome:
                                telnetcon = "True"
                            else:
                                telnetcon = "False"
                            if "200" in str(res):
                                print(f"Updating data entry...")  
                                # The data you want to send in the PUT request
                                data = {
                                    "ip": selected_ip,        # The IP address of the device you want to update
                                    "update_field": "vuln_TelnetPortOpen",        # The field you want to update (e.g., 'OS')
                                    "new_value": telnetcon       # The new value to assign to that field
                                }

                                # Sending the PUT request to the FastAPI server
                                response = requests.put("http://0.0.0.0:5000/updateDevice", json=data)
                                print("Database has been updated.")


                        elif  "Web Server (HTTP) SQL" in vuln and "Linux" in scan_results['os']:
                            sqli = "False"
                            webpage = input("\nPlease enter the webpage you want to exam for SQLi: ")
                            print(f"Testing SQL injection on {webpage}")
                            outcome = test_sql_injection(webpage)
                            print("\nTest Results:")
                            print(f"Vulnerable: {'Yes' if outcome['vulnerable'] else 'No'}")
                            if outcome['vulnerable']:
                                print("\nSuccessful Payloads:")
                                for payload in outcome['successful_payloads']:
                                    print(f"- {payload}")
                                print("\nVulnerability Types Detected:")
                                for tech, found in outcome['techniques'].items():
                                    if found:
                                        print(f"- {tech.replace('_', ' ').title()}")
                                sqli = "True"
                            if outcome['errors']:
                                print("\nErrors encountered:")
                                for error in outcome['errors']:
                                    print(f"- {error}")
                            if "200" in str(res):
                                print(f"Updating data entry...")  
                                # The data you want to send in the PUT request
                                data = {
                                    "ip": selected_ip,        # The IP address of the device you want to update
                                    "update_field": "vuln_WebServerHTTPSQLi",        # The field you want to update (e.g., 'OS')
                                    "new_value": sqli       # The new value to assign to that field
                                }

                                # Sending the PUT request to the FastAPI server
                                response = requests.put("http://0.0.0.0:5000/updateDevice", json=data)
                                print("Database has been updated.")


                        elif  "Web Server (HTTP) XSS" in vuln and "Linux" in scan_results['os']:
                            webpage = input("\nPlease enter the webpage you want to exam for XSS: ")
                            outcome = test_xss(webpage)
                            if outcome > 0:
                                xss = "True"
                            else:
                                xss = "False"
                            if "200" in str(res):
                                print(f"Updating data entry...")  
                                # The data you want to send in the PUT request
                                data = {
                                    "ip": selected_ip,        # The IP address of the device you want to update
                                    "update_field": "vuln_WebServerHTTPXSS",        # The field you want to update (e.g., 'OS')
                                    "new_value": xss       # The new value to assign to that field
                                }

                                # Sending the PUT request to the FastAPI server
                                response = requests.put("http://0.0.0.0:5000/updateDevice", json=data)
                                print("Database has been updated.")

                else:

                    # Ask user which vulnerability to validate
                    selected_vuln = input("\nWhich vulnerability do you want to validate? (Enter name or 'none' to skip): ")

                    if  "SSH Bruteforce" in selected_vuln and "Linux" in scan_results['os']:
                        outcome = ssh_brute_force(selected_ip, "user", password_list)
                        if outcome:
                            outcome_str = "True"
                        else:
                            outcome_str = "False"
                        dbInsert_check = input("\nDo you want to add the result to the database? (Y/N): ")
                        if dbInsert_check == "Y" or "y":
                            if "200" in str(res):
                                print(f"Updating data entry...")  
                                # The data you want to send in the PUT request
                                data = {
                                    "ip": selected_ip,        # The IP address of the device you want to update
                                    "update_field": "vuln_SSHBruteforce",        # The field you want to update (e.g., 'OS')
                                    "new_value": outcome_str       # The new value to assign to that field
                                }

                                # Sending the PUT request to the FastAPI server
                                response = requests.put("http://0.0.0.0:5000/updateDevice", json=data)
                                print("Database has been updated.")
                        else:
                            print(f"Database hasn't been updated.")
                        
                    elif  "FTP Port Open" in selected_vuln and "Linux" in scan_results['os']:
                        outcome = check_ftpcon(selected_ip, 21)
                        if outcome:
                            ftpcon = "True"
                        else:
                            ftpcon = "False"
                        dbInsert_check = input("\nDo you want to add the result to the database? (Y/N): ")
                        if dbInsert_check == "Y" or "y":
                            if "200" in str(res):
                                print(f"Updating data entry...")  
                                # The data you want to send in the PUT request
                                data = {
                                    "ip": selected_ip,        # The IP address of the device you want to update
                                    "update_field": "vuln_FTPPortOpen",        # The field you want to update (e.g., 'OS')
                                    "new_value": ftpcon       # The new value to assign to that field
                                }

                                # Sending the PUT request to the FastAPI server
                                response = requests.put("http://0.0.0.0:5000/updateDevice", json=data)
                                print("Database has been updated.")
                        else:
                            print(f"Database hasn't been updated.")

                    elif  "FTP Access" in selected_vuln and "Linux" in scan_results['os']:
                        outcome = check_ftpaccess(selected_ip, 21)
                        if outcome:
                            ftpaccess = "True"
                        else:
                            ftpaccess = "False"
                        dbInsert_check = input("\nDo you want to add the result to the database? (Y/N): ")
                        if dbInsert_check == "Y" or "y":
                            if "200" in str(res):
                                print(f"Updating data entry...")  
                                # The data you want to send in the PUT request
                                data = {
                                    "ip": selected_ip,        # The IP address of the device you want to update
                                    "update_field": "vuln_FTPAccess",        # The field you want to update (e.g., 'OS')
                                    "new_value": ftpaccess       # The new value to assign to that field
                                }

                                # Sending the PUT request to the FastAPI server
                                response = requests.put("http://0.0.0.0:5000/updateDevice", json=data)
                                print("Database has been updated.")
                        else:
                            print(f"Database hasn't been updated.")

                    elif  "Telnet Port Open" in selected_vuln and "Linux" in scan_results['os']:
                        outcome = telnet_connect(ip=selected_ip)
                        if outcome:
                            telnetcon = "True"
                        else:
                            telnetcon = "False"
                        dbInsert_check = input("\nDo you want to add the result to the database? (Y/N): ")
                        if dbInsert_check == "Y" or "y":
                            if "200" in str(res):
                                print(f"Updating data entry...")  
                                # The data you want to send in the PUT request
                                data = {
                                    "ip": selected_ip,        # The IP address of the device you want to update
                                    "update_field": "vuln_TelnetPortOpen",        # The field you want to update (e.g., 'OS')
                                    "new_value": telnetcon       # The new value to assign to that field
                                }

                                # Sending the PUT request to the FastAPI server
                                response = requests.put("http://0.0.0.0:5000/updateDevice", json=data)
                                print("Database has been updated.")
                        else:
                            print(f"Database hasn't been updated.")


                    elif  "Web Server (HTTP) SQL" in selected_vuln and "Linux" in scan_results['os']:
                        sqli = "False"
                        webpage = input("\nPlease enter the webpage you want to exam for SQLi: ")
                        print(f"Testing SQL injection on {webpage}")
                        outcome = test_sql_injection(webpage)
                        print("\nTest Results:")
                        print(f"Vulnerable: {'Yes' if outcome['vulnerable'] else 'No'}")
                        if outcome['vulnerable']:
                            print("\nSuccessful Payloads:")
                            for payload in outcome['successful_payloads']:
                                print(f"- {payload}")
                            print("\nVulnerability Types Detected:")
                            for tech, found in outcome['techniques'].items():
                                if found:
                                    print(f"- {tech.replace('_', ' ').title()}")
                            sqli = "True"
                        if outcome['errors']:
                            print("\nErrors encountered:")
                            for error in outcome['errors']:
                                print(f"- {error}")
                        dbInsert_check = input("\nDo you want to add the result to the database? (Y/N): ")
                        if dbInsert_check == "Y" or "y":
                            if "200" in str(res):
                                print(f"Updating data entry...")  
                                # The data you want to send in the PUT request
                                data = {
                                    "ip": selected_ip,        # The IP address of the device you want to update
                                    "update_field": "vuln_WebServerHTTPSQLi",        # The field you want to update (e.g., 'OS')
                                    "new_value": sqli       # The new value to assign to that field
                                }

                                # Sending the PUT request to the FastAPI server
                                response = requests.put("http://0.0.0.0:5000/updateDevice", json=data)
                                print("Database has been updated.")
                        else:
                            print(f"Database hasn't been updated.")

                    elif  "Web Server (HTTP) XSS" in selected_vuln and "Linux" in scan_results['os']:
                        webpage = input("\nPlease enter the webpage you want to exam for XSS: ")
                        outcome = test_xss(webpage)
                        if outcome > 0:
                            xss = "True"
                        else:
                            xss = "False"
                        dbInsert_check = input("\nDo you want to add the result to the database? (Y/N): ")
                        if dbInsert_check == "Y" or "y":
                            if "200" in str(res):
                                print(f"Updating data entry...")  
                                # The data you want to send in the PUT request
                                data = {
                                    "ip": selected_ip,        # The IP address of the device you want to update
                                    "update_field": "vuln_WebServerHTTPXSS",        # The field you want to update (e.g., 'OS')
                                    "new_value": xss       # The new value to assign to that field
                                }

                                # Sending the PUT request to the FastAPI server
                                response = requests.put("http://0.0.0.0:5000/updateDevice", json=data)
                                print("Database has been updated.")
                        else:
                            print(f"Database hasn't been updated.")

                    else:
                        print("\nNot able to validate")

            else:
                print("\n✅ No common vulnerabilities detected.")

        else:
            print("\n❌ Invalid IP address entered.")

        final_prompt = input("\nDo you want to validate other vulns? (Y/N): ")
        if final_prompt.upper() != "Y":
            print("Exiting...")
            break

if __name__ == "__main__":
    scan_and_report()
