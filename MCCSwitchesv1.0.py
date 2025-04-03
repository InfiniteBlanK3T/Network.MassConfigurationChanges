import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import netmiko
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException, ReadTimeout
import threading
import ipaddress
import queue
import time
import re
from typing import List, Set, Dict, Optional

# --- Device Class (Simplified) ---
# We can store status directly in the Treeview or a dictionary
# This class is less necessary now but can be expanded later if needed.

# --- Main Application Class ---
class NetworkConfigTool:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Network Configuration Tool V1 - ThomasVo3")
        self.root.geometry("850x700") # Increased size

        # Style configuration
        self.style = ttk.Style()
        # Use a theme that looks better on the OS if available
        available_themes = self.style.theme_names()
        if 'clam' in available_themes:
             self.style.theme_use('clam')
        elif 'vista' in available_themes:
             self.style.theme_use('vista')
        elif 'xpnative' in available_themes:
             self.style.theme_use('xpnative')

        self.style.configure('TButton', padding=5)
        self.style.configure('TLabel', padding=5)
        self.style.configure('TEntry', padding=5)
        self.style.configure('Treeview', rowheight=25)
        self.style.configure('Treeview.Heading', font=('TkDefaultFont', 10,'bold'))

        # Device tracking and communication queue
        self.devices_status: Dict[str, Dict] = {} # Store device info {ip: {'status': '...', 'error': '...', 'item_id': '...'}}
        self.ui_update_queue = queue.Queue() # Queue for thread-safe UI updates

        self.create_gui()
        self.check_ui_queue() # Start checking the queue for updates

    def create_gui(self):
        # Use grid weights for resizing
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        # Create main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        main_frame.columnconfigure(0, weight=1) # Make column 0 expandable
        main_frame.rowconfigure(2, weight=1) # Make row 2 (status) expandable
        main_frame.rowconfigure(4, weight=1) # Make row 4 (commands) expandable


        # --- Credentials and Settings Frame ---
        settings_frame = ttk.LabelFrame(main_frame, text="Settings & Credentials", padding="10")
        settings_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0,10))
        settings_frame.columnconfigure(1, weight=1) # Make entry column expandable
        settings_frame.columnconfigure(3, weight=1) # Make device type column expandable


        ttk.Label(settings_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.username_var = tk.StringVar()
        ttk.Entry(settings_frame, textvariable=self.username_var, width=30).grid(row=0, column=1, sticky=(tk.W, tk.E), padx=5, pady=2)

        ttk.Label(settings_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.password_var = tk.StringVar()
        ttk.Entry(settings_frame, textvariable=self.password_var, show="*", width=30).grid(row=1, column=1, sticky=(tk.W, tk.E), padx=5, pady=2)

        ttk.Label(settings_frame, text="Enable Secret:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        self.enable_password_var = tk.StringVar()
        ttk.Entry(settings_frame, textvariable=self.enable_password_var, show="*", width=30).grid(row=2, column=1, sticky=(tk.W, tk.E), padx=5, pady=2)

        # Device Type Dropdown
        ttk.Label(settings_frame, text="Device Type:").grid(row=0, column=2, sticky=tk.W, padx=(20, 5), pady=2)
        self.device_type_var = tk.StringVar()
        # Common Netmiko device types - add more as needed
        common_device_types = [
            "cisco_ios", "cisco_xr", "cisco_xe", "cisco_nxos",
            "arista_eos", "juniper_junos", "linux",
            "paloalto_panos", "fortinet_os (FS switches)", "vyos"
        ]
        self.device_type_combo = ttk.Combobox(settings_frame, textvariable=self.device_type_var, values=common_device_types, width=20)
        self.device_type_combo.grid(row=0, column=3, sticky=(tk.W, tk.E), padx=5, pady=2)
        self.device_type_combo.current(0) # Default to cisco_ios

        # --- IP Input Frame ---
        ip_frame = ttk.LabelFrame(main_frame, text="Target IP Addresses", padding="10")
        ip_frame.grid(row=1, column=0, sticky=(tk.W, tk.E), pady=(0,10))
        ip_frame.columnconfigure(0, weight=1) # Make entry expand

        ip_help_text = "Enter IPs/Ranges (e.g., 10.0.0.1; 192.168.1.10-20; 172.16.0.0/24):"
        ttk.Label(ip_frame, text=ip_help_text).grid(row=0, column=0, columnspan=2, sticky=tk.W, padx=5)

        self.ip_entry = ttk.Entry(ip_frame, width=80)
        self.ip_entry.grid(row=1, column=0, sticky=(tk.W, tk.E), padx=5, pady=5)

        ttk.Button(ip_frame, text="Load IPs from File", command=self.load_ips_from_file).grid(row=1, column=1, padx=5, pady=5)
        ttk.Button(ip_frame, text="Add IPs", command=self.add_ips_to_list).grid(row=1, column=2, padx=5, pady=5)


        # --- Status Frame (Treeview) ---
        status_frame = ttk.LabelFrame(main_frame, text="Device Status", padding="10")
        status_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0,10))
        status_frame.columnconfigure(0, weight=1)
        status_frame.rowconfigure(0, weight=1)


        columns = ('ip', 'status', 'details')
        self.status_tree = ttk.Treeview(status_frame, columns=columns, show='headings', height=10)

        self.status_tree.heading('ip', text='IP Address')
        self.status_tree.heading('status', text='Status')
        self.status_tree.heading('details', text='Details / Last Error')

        self.status_tree.column('ip', width=150, anchor=tk.W)
        self.status_tree.column('status', width=100, anchor=tk.W)
        self.status_tree.column('details', width=400, anchor=tk.W) # Wider details column

        # Add scrollbars
        vsb = ttk.Scrollbar(status_frame, orient="vertical", command=self.status_tree.yview)
        hsb = ttk.Scrollbar(status_frame, orient="horizontal", command=self.status_tree.xview)
        self.status_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.status_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        vsb.grid(row=0, column=1, sticky=(tk.N, tk.S))
        hsb.grid(row=1, column=0, sticky=(tk.W, tk.E))


        # --- Command Frame ---
        cmd_frame = ttk.LabelFrame(main_frame, text="Commands to Execute (one per line)", padding="10")
        cmd_frame.grid(row=3, column=0, sticky=(tk.W, tk.E), pady=(0,10))
        cmd_frame.columnconfigure(0, weight=1)
        cmd_frame.rowconfigure(0, weight=1) # Allow text area to expand vertically if needed (less critical)

        self.command_text = scrolledtext.ScrolledText(cmd_frame, height=6, width=80, wrap=tk.WORD)
        self.command_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=5, pady=5)
        # Example commands
        self.command_text.insert(tk.END, "show version\n")
        self.command_text.insert(tk.END, "show ip interface brief\n")

        # --- Buttons Frame ---
        btn_frame = ttk.Frame(main_frame, padding="10")
        btn_frame.grid(row=4, column=0, sticky=(tk.W, tk.E))
        # Center buttons
        btn_frame.columnconfigure(0, weight=1)
        btn_frame.columnconfigure(1, weight=1)
        btn_frame.columnconfigure(2, weight=1)
        btn_frame.columnconfigure(3, weight=1)


        self.connect_button = ttk.Button(btn_frame, text="Connect All", command=self.start_connections_thread)
        self.connect_button.grid(row=0, column=0, padx=10, pady=10)

        self.send_button = ttk.Button(btn_frame, text="Send Commands", command=self.start_commands_thread)
        self.send_button.grid(row=0, column=1, padx=10, pady=10)

        self.clear_status_button = ttk.Button(btn_frame, text="Clear Status", command=self.clear_status_list)
        self.clear_status_button.grid(row=0, column=2, padx=10, pady=10)

        self.clear_all_button = ttk.Button(btn_frame, text="Clear All", command=self.clear_all)
        self.clear_all_button.grid(row=0, column=3, padx=10, pady=10)

    # --- IP Parsing and Handling ---
    def parse_ip_input(self, ip_input: str) -> Set[str]:
        """Parses a string containing IPs, ranges (1.1.1.1-10), CIDR, separated by ';' or newlines."""
        ip_set = set()
        entries = re.split(r'[;\n]+', ip_input) # Split by semicolon or newline

        for entry in entries:
            entry = entry.strip()
            if not entry:
                continue

            try:
                if '-' in entry: # Range like 192.168.1.10-20
                    parts = entry.split('-')
                    if len(parts) == 2 and '.' in parts[0]:
                         base_ip_parts = parts[0].split('.')
                         start_str = base_ip_parts[-1]
                         end_str = parts[1]
                         if len(base_ip_parts) == 4 and start_str.isdigit() and end_str.isdigit():
                             prefix = ".".join(base_ip_parts[:-1]) + "."
                             start_ip_num = int(start_str)
                             end_ip_num = int(end_str)
                             if 0 <= start_ip_num <= 255 and 0 <= end_ip_num <= 255 and start_ip_num <= end_ip_num:
                                 for i in range(start_ip_num, end_ip_num + 1):
                                     ip_set.add(prefix + str(i))
                             else:
                                 raise ValueError("Invalid range values")
                         else:
                            raise ValueError("Invalid range format")
                    else:
                        raise ValueError("Invalid range format")

                elif '/' in entry: # CIDR like 192.168.1.0/24
                     network = ipaddress.ip_network(entry, strict=False) # Allow host bits set
                     for ip in network.hosts(): # Use .hosts() for usable IPs
                         ip_set.add(str(ip))
                     # Optionally add network/broadcast if needed, but usually hosts are desired
                     # ip_set.add(str(network.network_address))
                     # ip_set.add(str(network.broadcast_address))

                else: # Single IP
                    ip = ipaddress.ip_address(entry)
                    ip_set.add(str(ip))

            except ValueError as e:
                messagebox.showwarning("Invalid Input", f"Skipping invalid IP/Range/CIDR: '{entry}'\nError: {e}")

        return ip_set

    def load_ips_from_file(self):
        filepath = filedialog.askopenfilename(
            title="Open IP Address File",
            filetypes=[("Text Files", "*.txt"), ("CSV Files", "*.csv"), ("All Files", "*.*")]
        )
        if not filepath:
            return

        try:
            with open(filepath, 'r') as f:
                content = f.read()
            # Add loaded IPs to the entry box for parsing
            current_text = self.ip_entry.get()
            separator = "; " if current_text else ""
            self.ip_entry.insert(tk.END, separator + content)
            self.add_ips_to_list() # Automatically add them after loading
        except Exception as e:
            messagebox.showerror("File Error", f"Failed to read file: {filepath}\nError: {e}")

    def add_ips_to_list(self):
        """Parses IPs from the entry box and adds them to the Treeview."""
        ip_input = self.ip_entry.get()
        new_ips = self.parse_ip_input(ip_input)

        added_count = 0
        for ip in new_ips:
            if ip not in self.devices_status:
                item_id = self.status_tree.insert('', tk.END, values=(ip, 'Pending', ''))
                self.devices_status[ip] = {'status': 'Pending', 'error': None, 'item_id': item_id}
                added_count += 1

        if added_count > 0:
            self.ip_entry.delete(0, tk.END) # Clear entry after adding
            self.update_log(f"Added {added_count} new unique devices to the list.")
        elif new_ips:
             messagebox.showinfo("Info", "All IPs entered are already in the list.")
        else:
             messagebox.showwarning("Input", "No valid new IP addresses found in the input.")


    # --- UI Update Handling ---
    def check_ui_queue(self):
        """Periodically check the queue for messages from worker threads."""
        try:
            while True:
                message = self.ui_update_queue.get_nowait()
                self.process_ui_update(message)
        except queue.Empty:
            pass # No messages currently
        finally:
            # Reschedule check
            self.root.after(100, self.check_ui_queue)

    def process_ui_update(self, message: Dict):
        """Processes a message from the queue to update the Treeview."""
        msg_type = message.get('type')
        ip = message.get('ip')

        if not ip or ip not in self.devices_status:
            print(f"Warning: Received UI update for unknown IP: {ip}") # Debug print
            return # Ignore updates for IPs not in our list

        item_id = self.devices_status[ip]['item_id']

        if msg_type == 'status_update':
            new_status = message.get('status', 'Unknown')
            details = message.get('details', '')
            self.devices_status[ip]['status'] = new_status
            self.devices_status[ip]['error'] = details if new_status == 'Failed' else None
            try:
                 # Ensure item still exists before updating
                 if self.status_tree.exists(item_id):
                     self.status_tree.item(item_id, values=(ip, new_status, details))
                 else:
                     print(f"Warning: Treeview item {item_id} for IP {ip} no longer exists.") # Debug print
            except tk.TclError as e:
                 print(f"Error updating Treeview for {ip} ({item_id}): {e}") # Debug print

        elif msg_type == 'log':
             self.update_log(message.get('message', ''))

        # Add other message types if needed (e.g., progress bar updates)

    def update_log(self, message: str):
        """Placeholder for potentially adding a separate log area later."""
        # Currently just prints, could insert into a dedicated log ScrolledText
        print(f"LOG: {message}")
        # self.log_text_area.insert(tk.END, f"{time.strftime('%H:%M:%S')} - {message}\n")
        # self.log_text_area.see(tk.END)


    # --- Connection Logic ---
    def start_connections_thread(self):
        """Starts the connection process in a separate thread."""
        if not self.devices_status:
             messagebox.showerror("Error", "No devices added to the list. Please add IPs first.")
             return
        if not all([self.username_var.get(), self.password_var.get(), self.device_type_var.get()]):
            messagebox.showerror("Error", "Username, Password, and Device Type are required.")
            return

        # Disable button during operation
        self.connect_button.config(state=tk.DISABLED)
        self.send_button.config(state=tk.DISABLED) # Also disable send during connect

        # Reset status for devices that are pending or failed before retry
        for ip, data in self.devices_status.items():
             if data['status'] in ['Pending', 'Failed']:
                 self.ui_update_queue.put({
                     'type': 'status_update',
                     'ip': ip,
                     'status': 'Connecting...',
                     'details': ''
                 })

        # Start the background thread
        connect_thread = threading.Thread(target=self.run_connections, daemon=True)
        connect_thread.start()

    def run_connections(self):
        """Worker function to connect to devices."""
        username = self.username_var.get()
        password = self.password_var.get()
        enable_secret = self.enable_password_var.get()
        device_type = self.device_type_var.get()

        connection_threads = []
        devices_to_connect = list(self.devices_status.keys()) # Connect to all listed devices

        for ip in devices_to_connect:
            # Only attempt connection if not already connected or in progress
            current_status = self.devices_status[ip]['status']
            if current_status not in ['Connected', 'Connecting...']: # Allow re-attempt on 'Failed' etc.
                # Update status to 'Connecting...' via queue immediately before starting thread
                self.ui_update_queue.put({
                    'type': 'status_update',
                    'ip': ip,
                    'status': 'Connecting...',
                    'details': ''
                 })
                thread = threading.Thread(target=self.connect_single_device,
                                          args=(ip, device_type, username, password, enable_secret),
                                          daemon=True)
                connection_threads.append(thread)
                thread.start()
                time.sleep(0.05) # Small delay to stagger thread starts slightly
        # --- REMOVED THE BLICKING JOIN LOOP ---
        # Wait for connection attempts to finish (optional, can update UI progressively)
        # for thread in connection_threads:
        #     thread.join() # DO NOT WAIT HERE
        # 
        # --- Re-enable buttons
        self.ui_update_queue.put({'type': 'log', 'message': "Connection attempts finished."})
        self.connect_button.config(state=tk.NORMAL)
        # Only enable Send if there are connected devices
        if any(d['status'] == 'Connected' for d in self.devices_status.values()):
             self.send_button.config(state=tk.NORMAL)


    def connect_single_device(self, ip: str, device_type: str, user: str, pwd: str, enable: Optional[str]):
        """Connects to a single device using Netmiko."""
        device_info = {
            'device_type': device_type,
            'host': ip,
            'username': user,
            'password': pwd,
            'secret': enable if enable else None, # Netmiko uses 'secret' for enable password
            'timeout': 10, # Increased timeout
            'session_timeout': 60, # Netmiko internal session timeout
            'blocking_timeout': 30, # Timeout for waiting on commands
            'fast_cli': False, # Can improve speed but sometimes less reliable
        }

        status = "Failed"
        details = ""
        try:
            # Remove None secret if not provided
            if device_info['secret'] is None:
                del device_info['secret']

            # --- Establish Connection ---
            # Using a context manager ensures disconnect
            with netmiko.ConnectHandler(**device_info) as net_connect:
                # --- Enter Enable Mode (if secret provided) ---
                if enable:
                    if not net_connect.check_enable_mode():
                        net_connect.enable() # Netmiko handles sending the secret

                # --- Check if still connected and in enable mode (if expected) ---
                if net_connect.is_alive():
                     if enable and not net_connect.check_enable_mode():
                         status = "Failed"
                         details = "Failed to enter enable mode."
                     else:
                        status = "Connected"
                        details = f"Connected successfully. Prompt: {net_connect.base_prompt}"
                        # We don't store the connection object globally anymore
                        # Commands will reconnect or use existing logic
                else:
                    status = "Failed"
                    details = "Connection lost after connect."

        except NetmikoTimeoutException:
            details = "Connection timed out."
        except NetmikoAuthenticationException:
            details = "Authentication failed (check user/pass/secret)."
        except Exception as e:
            details = f"An unexpected error occurred: {str(e)}"
        finally:
            # --- Send status update back to the main thread ---
            self.ui_update_queue.put({
                'type': 'status_update',
                'ip': ip,
                'status': status,
                'details': details
            })

    # --- Command Execution Logic ---
    def start_commands_thread(self):
        """Starts sending commands in a separate thread."""
        commands_raw = self.command_text.get(1.0, tk.END).strip()
        if not commands_raw:
            messagebox.showerror("Error", "No commands entered.")
            return

        commands = [cmd for cmd in commands_raw.split('\n') if cmd.strip()]
        if not commands:
             messagebox.showerror("Error", "No valid commands entered.")
             return

        connected_devices = [ip for ip, data in self.devices_status.items() if data['status'] == 'Connected']
        if not connected_devices:
            messagebox.showerror("Error", "No devices are currently connected.")
            return

        # Disable buttons
        self.connect_button.config(state=tk.DISABLED)
        self.send_button.config(state=tk.DISABLED)

        # Update status for connected devices
        for ip in connected_devices:
             self.ui_update_queue.put({'type': 'status_update','ip': ip, 'status': 'Running Cmds...', 'details': ''})

        # Start the background thread
        command_thread = threading.Thread(target=self.run_commands, args=(commands,), daemon=True)
        command_thread.start()

    def run_commands(self, commands: List[str]):
        """Worker function to send commands to connected devices."""
        username = self.username_var.get()
        password = self.password_var.get()
        enable_secret = self.enable_password_var.get()
        device_type = self.device_type_var.get()

        command_threads = []
        devices_to_run = [ip for ip, data in self.devices_status.items() if data['status'] == 'Running Cmds...']

        for ip in devices_to_run:
            thread = threading.Thread(target=self.send_commands_to_device,
                                      args=(ip, device_type, username, password, enable_secret, commands),
                                      daemon=True)
            command_threads.append(thread)
            thread.start()
            time.sleep(0.05) # Stagger threads

        # Wait for command threads
        for thread in command_threads:
            thread.join()

        # Re-enable buttons via the queue
        self.ui_update_queue.put({'type': 'log', 'message': "Command execution finished."})
        self.connect_button.config(state=tk.NORMAL)
        self.send_button.config(state=tk.NORMAL)


    def send_commands_to_device(self, ip: str, device_type: str, user: str, pwd: str, enable: Optional[str], commands: List[str]):
        """Sends a list of commands to a single device using Netmiko."""
        device_info = {
            'device_type': device_type,
            'host': ip,
            'username': user,
            'password': pwd,
            'secret': enable if enable else None,
            'timeout': 10,
            'session_timeout': 120, # Longer timeout for commands
            'blocking_timeout': 90,
            'fast_cli': False,
        }
        status = "Cmds Failed" # Default status if things go wrong
        details = ""
        full_output = f"--- Output for {ip} ---\n"

        try:
            if device_info['secret'] is None:
                del device_info['secret']

            with netmiko.ConnectHandler(**device_info) as net_connect:
                if enable:
                     if not net_connect.check_enable_mode(): net_connect.enable()
                     if not net_connect.check_enable_mode(): raise Exception("Failed to enter enable mode.")

                # --- Send Commands ---
                for cmd in commands:
                    self.ui_update_queue.put({'type': 'status_update','ip': ip, 'status': 'Running Cmds...', 'details': f"Running: {cmd[:30]}..."})
                    # Use send_command for commands expecting output
                    # Use send_config_set for configuration commands (more robust)
                    # Determine if command is config or show (simple check)
                    is_config_cmd = any(kw in cmd.lower() for kw in ['config', 'interface', 'crypto', 'ip route', 'vlan', 'no ']) # Add more keywords

                    output = ""
                    if is_config_cmd:
                         output = net_connect.send_config_set([cmd], exit_config_mode=False, cmd_verify=False) # Use cmd_verify=True for safer config
                         # Consider adding net_connect.save_config() if needed after config commands
                    else:
                         output = net_connect.send_command(cmd, read_timeout=90) # Long read timeout for show commands

                    full_output += f"\n{net_connect.base_prompt}{cmd}\n{output}\n"

                status = "Cmds Sent OK"
                details = "Commands executed (check log/output)."
                 # Optionally save full output to a file here
                # with open(f"{ip}_output.log", "w") as f:
                #     f.write(full_output)
                # print(full_output) # Print to console for now

        except NetmikoTimeoutException:
            details = "Timeout during command execution."
        except NetmikoAuthenticationException:
             details = "Authentication failed (check user/pass/secret)." # Should have been caught at connect, but maybe session timed out
        except ReadTimeout:
             details = f"Read Timeout waiting for command output (check command: {cmd[:30]}...). Output so far:\n{full_output[-500:]}" # Show last bit of output
        except Exception as e:
            details = f"Error sending commands: {str(e)}. Output so far:\n{full_output[-500:]}"
        finally:
            self.ui_update_queue.put({
                'type': 'status_update',
                'ip': ip,
                'status': status,
                'details': details
            })
            # Optionally log full_output to a file or dedicated log area
            print(f"\n--- Final output/status for {ip} ---\nStatus: {status}\nDetails: {details}\nOutput Snippet:\n{full_output[-500:]}\n---------------------\n")

    # --- Clearing Functions ---
    def clear_status_list(self):
        """Clears the Treeview and the internal device status dictionary."""
        if messagebox.askyesno("Confirm Clear", "Clear all devices from the status list?"):
            for item in self.status_tree.get_children():
                self.status_tree.delete(item)
            self.devices_status.clear()

    def clear_all(self):
        """Clears status, commands, IPs, and credentials."""
        if messagebox.askyesno("Confirm Clear All", "Clear all fields, credentials, and device statuses?"):
            self.clear_status_list() # Clears tree and dict
            self.command_text.delete(1.0, tk.END)
            self.ip_entry.delete(0, tk.END)
            self.username_var.set("")
            self.password_var.set("")
            self.enable_password_var.set("")
            self.device_type_combo.current(0) # Reset device type

    # --- Main Loop ---
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = NetworkConfigTool()
    app.run()