import paramiko
import ipaddress
from tkinter import messagebox # Keep messagebox for IP parsing errors for now
from typing import List, Set, Optional, Dict, Any

class NetworkDevice:
    """Represents a network device and its state."""
    def __init__(self, ip: str):
        self.ip: str = ip
        self.status: str = "Pending"
        self.connection: Optional[paramiko.Channel] = None
        self.ssh_client: Optional[paramiko.SSHClient] = None # Keep client reference for closing
        self.error: Optional[str] = None

    def close_connection(self):
        """Safely close the SSH connection."""
        if self.connection:
            try:
                self.connection.close()
            except Exception:
                pass # Ignore errors on close
            self.connection = None
        if self.ssh_client:
            try:
                self.ssh_client.close()
            except Exception:
                pass # Ignore errors on close
            self.ssh_client = None
        self.status = "Disconnected" if self.status != "Failed" else self.status

def parse_ip_range(ip_range_str: str) -> Set[str]:
    """Parses IP ranges and individual IPs from a semicolon-separated string."""
    ip_set = set()
    ranges = ip_range_str.split(';')

    for r in ranges:
        r = r.strip()
        if not r:
            continue
        if '-' in r:
            try:
                # Improved range parsing (basic last octet assumption)
                parts = r.split('-')
                if len(parts) != 2: raise ValueError("Invalid range format")
                
                start_ip_str = parts[0]
                end_num_str = parts[1]

                # Check if end part is just a number or a full IP for more robust parsing later if needed
                if '.' in end_num_str:
                    raise ValueError("Only suffix range (e.g., 192.168.1.10-20) supported currently")
                
                end_num = int(end_num_str)
                start_ip_parts = start_ip_str.split('.')
                if len(start_ip_parts) != 4: raise ValueError("Invalid start IP")

                start_num = int(start_ip_parts[-1])
                base_ip = ".".join(start_ip_parts[:-1])

                if not (0 <= start_num <= 255 and 0 <= end_num <= 255 and start_num <= end_num):
                    raise ValueError("Invalid octet values in range")

                for i in range(start_num, end_num + 1):
                    ip = f"{base_ip}.{i}"
                    ipaddress.ip_address(ip) # Validate generated IP
                    ip_set.add(ip)
            except ValueError as e:
                messagebox.showerror("Error", f"Invalid IP range format in '{r}': {e}")
                return set() # Stop parsing on error
        else:
            # Single IP
            try:
                ipaddress.ip_address(r) # Validate
                ip_set.add(r)
            except ValueError:
                messagebox.showerror("Error", f"Invalid IP address format: {r}")
                return set() # Stop parsing on error
    return ip_set

def connect_device(device: NetworkDevice, creds: Dict[str, Any], status_callback: callable):
    """Attempts to connect to a single device and updates status via callback."""
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        status_callback(f"Connecting to {device.ip}...")
        ssh.connect(
            device.ip,
            username=creds['username'],
            password=creds['password'],
            timeout=10,
            allow_agent=False,
            look_for_keys=False,
            banner_timeout=15
        )
        device.ssh_client = ssh # Store client reference

        # Get shell and attempt enable mode
        shell = ssh.invoke_shell()
        shell.settimeout(5) # Set timeout for recv

        # Simple check for initial prompt before sending enable
        try:
             shell.recv(1024)
        except Exception:
            pass # Ignore timeout if no initial output received quickly

        shell.send("enable\n")

        # Basic attempt to read password prompt
        try:
            shell.recv(1024)
        except Exception:
            pass # Ignore timeout/errors

        shell.send(f"{creds['enable_password']}\n")

        # Basic attempt read after enable password
        try:
            shell.recv(1024)
        except Exception:
            pass # Ignore timeout/errors

        device.connection = shell
        device.status = "Connected"
        status_callback(f"Successfully connected to {device.ip}")

    except paramiko.AuthenticationException:
        device.status = "Failed"
        device.error = "Authentication Failed"
        status_callback(f"Failed (Auth) connecting to {device.ip}")
    except Exception as e:
        device.status = "Failed"
        device.error = str(e)
        status_callback(f"Failed to connect to {device.ip}: {e}")
    finally:
        # Ensure connection is closed if setup failed mid-way but client was created
         if device.status == "Failed" and device.ssh_client and not device.connection:
              device.close_connection()


def send_commands_to_device(device: NetworkDevice, commands: List[str], status_callback: callable):
    """Sends a list of commands to a single connected device."""
    if device.status != "Connected" or not device.connection:
        status_callback(f"Skipping {device.ip} (not connected).")
        return

    status_callback(f"\n--- Sending to {device.ip} ---")
    try:
        output_buffer = ""
        for cmd in commands:
            cmd = cmd.strip()
            if not cmd:
                continue

            status_callback(f"[{device.ip}] > {cmd}")
            device.connection.send(f"{cmd}\n")
            # Improved read loop - attempt to read until prompt or timeout
            # NOTE: This is still basic, real prompt detection is more robust
            output_chunk = ""
            try:
                 # Wait a short time for command execution before reading
                 # time.sleep(0.5) # Use if needed, but recv timeout is often enough
                 output_chunk = device.connection.recv(65535).decode('utf-8', errors='replace')
                 output_buffer += output_chunk
            except TimeoutError: # socket.timeout inherits from TimeoutError in later Pythons
                 status_callback(f"[{device.ip}] (Timeout waiting for output after '{cmd}')")
            except Exception as read_e:
                 status_callback(f"[{device.ip}] Error reading output: {read_e}")
                 device.status = "Error"
                 device.error = f"Read error: {read_e}"
                 break # Stop sending commands to this device on read error

        if output_buffer:
             status_callback(f"Output from {device.ip}:\n{output_buffer.strip()}")
        else:
             status_callback(f"[{device.ip}] (No output received)")

    except Exception as e:
        status_callback(f"Error sending commands to {device.ip}: {str(e)}")
        device.status = "Error"
        device.error = str(e)
    finally:
         status_callback(f"--- Finished {device.ip} ---")