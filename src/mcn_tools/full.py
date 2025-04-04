import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, PanedWindow
import paramiko
import threading
import ipaddress
import queue
import time
from datetime import datetime
from typing import List, Set, Dict, Optional, Tuple, Any

# --- Constants ---
STATUS_PENDING = "Pending"
STATUS_CONNECTING = "Connecting"
STATUS_CONNECTED = "Connected"
STATUS_FAILED = "Failed"
STATUS_EXECUTING = "Executing"
STATUS_ERROR = "Error"

# --- Data Class ---
class NetworkDevice:
    """Represents a network device and its state."""
    def __init__(self, ip: str):
        self.ip: str = ip
        self.status: str = STATUS_PENDING
        self.message: str = "Waiting to connect..."
        self.ssh_client: Optional[paramiko.SSHClient] = None
        self.shell: Optional[paramiko.Channel] = None
        self.output_buffer: str = ""
        self.last_update_time: Optional[datetime] = None
        self.treeview_item_id: Optional[str] = None # To easily update the treeview

    def update_state(self, status: str, message: str = ""):
        self.status = status
        self.message = message if message else status # Use status as message if none provided
        self.last_update_time = datetime.now()

    def add_output(self, output: str):
        self.output_buffer += output

    def clear_output(self):
        self.output_buffer = ""

    def close_connection(self):
        if self.shell:
            try:
                self.shell.close()
            except Exception:
                pass # Ignore errors during close
            self.shell = None
        if self.ssh_client:
            try:
                self.ssh_client.close()
            except Exception:
                pass # Ignore errors during close
            self.ssh_client = None
        if self.status not in [STATUS_FAILED, STATUS_ERROR]:
             self.update_state("Disconnected", "Connection closed.")


# --- Network Logic ---
class DeviceManager:
    """Handles network connections and command execution."""
    def __init__(self, status_queue: queue.Queue, output_queue: queue.Queue):
        self.devices: Dict[str, NetworkDevice] = {}
        self.status_queue = status_queue # For general status and Treeview updates
        self.output_queue = output_queue # For individual device console output
        self.is_connecting = False
        self.is_sending_commands = False
        self._stop_event = threading.Event() # To signal cancellation

    def _put_status(self, type: str, data: Any):
        self.status_queue.put((type, data))

    def _put_output(self, ip: str, output: str):
        self.output_queue.put((ip, output))

    def parse_ip_range(self, ip_range_str: str) -> Set[str]:
        """Parses IP ranges and individual IPs."""
        ip_set = set()
        potential_ips = [p.strip() for p in ip_range_str.split(';') if p.strip()]

        for item in potential_ips:
            if '-' in item:
                try:
                    parts = item.split('-')
                    if len(parts) != 2:
                        raise ValueError("Range must have exactly one hyphen.")

                    start_ip_str = parts[0].strip()
                    end_part = parts[1].strip()

                    start_ip = ipaddress.ip_address(start_ip_str)

                    # Handle range end: 192.168.1.10-20 or 192.168.1.10-192.168.1.20
                    if '.' in end_part:
                        end_ip = ipaddress.ip_address(end_part)
                        if start_ip.version != end_ip.version:
                             raise ValueError("Start and end IP versions differ.")
                        if start_ip > end_ip:
                            raise ValueError("Start IP is greater than end IP in range.")
                        for ip_int in range(int(start_ip), int(end_ip) + 1):
                            ip_set.add(str(ipaddress.ip_address(ip_int)))
                    else:
                        # Assume end is the last octet/part
                        end_num = int(end_part)
                        if not (0 <= end_num <= 255 if start_ip.version == 4 else True): # Basic IPv4 check
                             raise ValueError("Invalid end number for range.")

                        base_parts = start_ip_str.split('.')
                        if len(base_parts) != 4: # Currently only supports simple IPv4 suffix ranges well
                             raise ValueError("Simple range only supported for IPv4 (e.g., 192.168.1.10-20).")

                        start_num = int(base_parts[-1])
                        if start_num > end_num:
                            raise ValueError("Start number is greater than end number in range.")

                        prefix = ".".join(base_parts[:-1])
                        for i in range(start_num, end_num + 1):
                             ip_set.add(f"{prefix}.{i}")

                except ValueError as e:
                    self._put_status("log_error", f"Invalid IP range format '{item}': {e}")
                    return set() # Return empty on error
            else:
                # Single IP
                try:
                    ipaddress.ip_address(item) # Validate
                    ip_set.add(item)
                except ValueError:
                    self._put_status("log_error", f"Invalid IP address format: '{item}'")
                    return set() # Return empty on error

        return ip_set

    def _read_shell_output(self, device: NetworkDevice) -> str:
        """Reads available data from the shell with a short timeout."""
        output = ""
        if device.shell and device.shell.recv_ready():
            try:
                output = device.shell.recv(65535).decode('utf-8', errors='replace')
                device.add_output(output)
                self._put_output(device.ip, output) # Send to individual console tab
            except Exception as e:
                 output = f"\nError reading from {device.ip}: {e}\n"
                 device.add_output(output)
                 self._put_output(device.ip, output)
                 device.update_state(STATUS_ERROR, f"Read error: {e}")
                 self._put_status("update_device", device)
        return output


    def _connect_single_device(self, device: NetworkDevice, creds: Dict):
        """Attempts to connect to a single device."""
        ip = device.ip
        self._put_status("log_info", f"[{ip}] Attempting connection...")
        device.update_state(STATUS_CONNECTING, "Initiating SSH...")
        self._put_status("update_device", device)

        try:
            device.ssh_client = paramiko.SSHClient()
            device.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            device.ssh_client.connect(
                hostname=ip,
                port=creds.get('port', 22),
                username=creds['username'],
                password=creds['password'],
                timeout=15,
                allow_agent=False,
                look_for_keys=False,
                banner_timeout=20
            )

            # --- Invoke Shell and Handle Enable Mode ---
            device.shell = device.ssh_client.invoke_shell()
            device.update_state(STATUS_CONNECTING, "Shell invoked, checking for prompt...")
            self._put_status("update_device", device)
            time.sleep(0.5) # Small delay for initial prompt
            initial_output = self._read_shell_output(device)

            # Send 'enable'
            if creds.get('enable_password'):
                device.update_state(STATUS_CONNECTING, "Sending 'enable'...")
                self._put_status("update_device", device)
                device.shell.send("enable\n")
                time.sleep(1.0) # Wait for password prompt
                enable_prompt_output = self._read_shell_output(device)

                # Send enable password
                device.update_state(STATUS_CONNECTING, "Sending enable password...")
                self._put_status("update_device", device)
                device.shell.send(f"{creds['enable_password']}\n")
                time.sleep(1.5) # Wait for login processing and prompt
                enable_pass_output = self._read_shell_output(device)

                # Basic check if enable likely succeeded (e.g., prompt changed to '#')
                if '#' not in enable_pass_output.split('\n')[-1]: # Very basic check
                    # Might not have worked, but proceed anyway - user can see output
                    self._put_status("log_warn", f"[{ip}] Enable mode might not be active (prompt check failed). Check console.")
                    device.update_state(STATUS_CONNECTED, "Connected (Enable status uncertain)")
                else:
                     device.update_state(STATUS_CONNECTED, "Connected (Enabled)")
            else:
                 # No enable password provided
                 device.update_state(STATUS_CONNECTED, "Connected (Enable not attempted)")

            self._put_status("log_info", f"[{ip}] Connection successful.")
            self._put_status("update_device", device)
            self._put_status("add_console_tab", device) # Add tab after successful connect

        except paramiko.AuthenticationException:
            error_msg = "Authentication failed (Bad username/password)."
            device.update_state(STATUS_FAILED, error_msg)
            self._put_status("log_error", f"[{ip}] {error_msg}")
            self._put_status("update_device", device)
            device.close_connection()
        except (paramiko.SSHException, paramiko.ssh_exception.NoValidConnectionsError) as e:
            error_msg = f"SSH connection error: {e}"
            device.update_state(STATUS_FAILED, error_msg)
            self._put_status("log_error", f"[{ip}] {error_msg}")
            self._put_status("update_device", device)
            device.close_connection()
        except (socket.timeout, TimeoutError):
            error_msg = "Connection timed out."
            device.update_state(STATUS_FAILED, error_msg)
            self._put_status("log_error", f"[{ip}] {error_msg}")
            self._put_status("update_device", device)
            device.close_connection()
        except Exception as e:
            error_msg = f"An unexpected error occurred: {e}"
            device.update_state(STATUS_FAILED, error_msg)
            self._put_status("log_error", f"[{ip}] {error_msg}")
            self._put_status("update_device", device)
            device.close_connection()

    def _connection_worker(self, ips_to_connect: List[str], creds: Dict):
        """Worker thread function to connect to multiple devices."""
        self.is_connecting = True
        self._stop_event.clear()
        self._put_status("connection_start", len(ips_to_connect))

        threads = []
        for ip in ips_to_connect:
            if self._stop_event.is_set():
                self._put_status("log_warn", f"[{ip}] Connection cancelled.")
                device = self.devices[ip]
                device.update_state(STATUS_FAILED, "Cancelled by user")
                self._put_status("update_device", device)
                continue # Skip starting new threads if cancelled

            device = self.devices[ip]
            thread = threading.Thread(target=self._connect_single_device, args=(device, creds), daemon=True)
            threads.append(thread)
            thread.start()
            time.sleep(0.1) # Slightly stagger thread starts

        # Wait for all connection threads to finish
        for thread in threads:
            thread.join()

        self.is_connecting = False
        self._put_status("connection_end", None) # Signal completion

    def start_connections(self, ip_list: Set[str], creds: Dict):
        """Initiates the connection process in a separate thread."""
        if self.is_connecting:
            self._put_status("log_error", "Connection process already running.")
            return

        # Clear previous state for the given IPs
        self.devices.clear() # Or selectively update if needed
        self._put_status("clear_devices", None)
        for ip in ip_list:
            self.devices[ip] = NetworkDevice(ip)
            self._put_status("add_device", self.devices[ip])

        # Start the connection worker thread
        worker = threading.Thread(target=self._connection_worker, args=(list(ip_list), creds), daemon=True)
        worker.start()

    def cancel_operations(self):
        """Signals any running operations (connection/commands) to stop."""
        if self.is_connecting or self.is_sending_commands:
            self._put_status("log_warn", "Cancellation requested...")
            self._stop_event.set()
        else:
            self._put_status("log_info", "Nothing to cancel.")


    def _send_commands_worker(self, commands: List[str]):
        """Worker thread to send commands to connected devices."""
        self.is_sending_commands = True
        self._stop_event.clear()
        self._put_status("command_start", None)
        self._put_status("log_info", "Starting command execution...")

        active_devices = [d for d in self.devices.values() if d.status == STATUS_CONNECTED]

        for device in active_devices:
            if self._stop_event.is_set():
                self._put_status("log_warn", f"[{device.ip}] Command execution cancelled.")
                break # Stop processing more devices

            if device.status != STATUS_CONNECTED or not device.shell:
                self._put_status("log_warn", f"[{device.ip}] Skipping commands (not connected).")
                continue

            self._put_status("log_info", f"[{device.ip}] Executing commands...")
            device.update_state(STATUS_EXECUTING, f"Running {len(commands)} commands...")
            self._put_status("update_device", device)
            self._put_output(device.ip, f"\n--- Executing Commands ({datetime.now()}) ---\n")

            try:
                for cmd in commands:
                    if self._stop_event.is_set():
                        self._put_status("log_warn", f"[{device.ip}] Command execution cancelled during sequence.")
                        self._put_output(device.ip, f"\n--- Command execution cancelled ---\n")
                        break # Stop sending more commands to this device

                    trimmed_cmd = cmd.strip()
                    if not trimmed_cmd:
                        continue

                    self._put_status("log_info", f"[{device.ip}] Sending: {trimmed_cmd}")
                    self._put_output(device.ip, f"\n> {trimmed_cmd}\n")
                    device.shell.send(f"{trimmed_cmd}\n")
                    time.sleep(1.5) # Increased wait - adjust as needed, prompt detection is better
                    self._read_shell_output(device) # Read output after command

                if not self._stop_event.is_set():
                    device.update_state(STATUS_CONNECTED, "Commands finished.") # Revert to connected
                    self._put_status("log_info", f"[{device.ip}] Commands finished.")
                else:
                     device.update_state(STATUS_ERROR, "Commands cancelled.") # Indicate cancellation
                     self._put_status("log_warn", f"[{device.ip}] Commands cancelled.")

                self._put_status("update_device", device)
                self._put_output(device.ip, f"\n--- End Command Execution ---\n")

            except Exception as e:
                error_msg = f"Error sending command to {device.ip}: {e}"
                self._put_status("log_error", error_msg)
                self._put_output(device.ip, f"\n--- ERROR: {error_msg} ---\n")
                device.update_state(STATUS_ERROR, f"Command error: {e}")
                self._put_status("update_device", device)
                # Consider closing connection on error? Depends on desired behavior.
                # device.close_connection()

        self.is_sending_commands = False
        self._put_status("log_info", "Command execution process finished.")
        self._put_status("command_end", None) # Signal completion


    def send_commands(self, commands: List[str]):
        """Initiates sending commands in a separate thread."""
        if self.is_sending_commands:
            self._put_status("log_error", "Command execution already in progress.")
            return
        if self.is_connecting:
             self._put_status("log_error", "Cannot send commands while connecting.")
             return

        connected_devices = [d for d in self.devices.values() if d.status == STATUS_CONNECTED]
        if not connected_devices:
            self._put_status("log_warn", "No devices are connected.")
            return
        if not commands or all(not c.strip() for c in commands):
             self._put_status("log_error", "No commands entered.")
             return

        # Start the command worker thread
        worker = threading.Thread(target=self._send_commands_worker, args=(commands,), daemon=True)
        worker.start()

    def cleanup(self):
        """Closes all active connections."""
        self._put_status("log_info", "Cleaning up connections...")
        self.cancel_operations() # Attempt to stop ongoing tasks
        time.sleep(0.2) # Give cancel signal time to propagate slightly
        for device in self.devices.values():
             if device.shell or device.ssh_client:
                 device.close_connection()
                 self._put_status("update_device", device)
        self._put_status("log_info", "Cleanup complete.")


# --- GUI Application ---
class NetworkConfigApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Network Configuration Tool v2.0 - Thomas.Vo3")
        self.root.geometry("1200x900") # Increased size

        # Style
        self.style = ttk.Style()
        self.style.theme_use('clam') # Or 'alt', 'default', 'classic'
        self.style.configure('TButton', padding=6, relief="flat", background="#ccc")
        self.style.map('TButton', background=[('active', '#eee')])
        self.style.configure('Treeview.Heading', font=('TkDefaultFont', 10, 'bold'))
        self.style.configure('Status.TLabel', font=('TkDefaultFont', 9))
        self.style.configure('Title.TLabel', font=('TkDefaultFont', 11, 'bold'))

        # Queues for thread communication
        self.status_queue = queue.Queue()
        self.output_queue = queue.Queue()

        # Network Logic Handler
        self.device_manager = DeviceManager(self.status_queue, self.output_queue)

        # State Variables
        self.username_var = tk.StringVar(value="your_username") # Default values for faster testing
        self.password_var = tk.StringVar(value="your_password")
        self.enable_password_var = tk.StringVar(value="your_enable_password")
        self.ip_range_var = tk.StringVar(value="192.168.1.1; 192.168.1.5-7") # Example

        self.create_widgets()
        self.update_status_bar() # Initialize status bar

        # Start the queue checker loop
        self.check_queues()

        # Cleanup on close
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def create_widgets(self):
        # Main Paned Window (Top: Config/Status, Bottom: Logs/Consoles)
        main_paned_window = PanedWindow(self.root, orient=tk.VERTICAL, sashrelief=tk.RAISED, sashwidth=6)
        main_paned_window.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # --- Top Pane --- (Inputs and Device List)
        top_frame = ttk.Frame(main_paned_window, padding=5)
        main_paned_window.add(top_frame)

        # Top Paned Window (Left: Config, Right: Status)
        top_paned_window = PanedWindow(top_frame, orient=tk.HORIZONTAL, sashrelief=tk.RAISED, sashwidth=6)
        top_paned_window.pack(fill=tk.BOTH, expand=True)

        # Left Side (Credentials, IPs, Commands, Buttons)
        config_frame = ttk.Frame(top_paned_window, padding=5)
        top_paned_window.add(config_frame)

        # Credentials
        cred_frame = ttk.LabelFrame(config_frame, text="Credentials", padding=10)
        cred_frame.pack(fill=tk.X, pady=5)
        ttk.Label(cred_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(cred_frame, textvariable=self.username_var, width=30).grid(row=0, column=1, sticky=tk.EW, padx=5, pady=2)
        ttk.Label(cred_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(cred_frame, textvariable=self.password_var, show="*", width=30).grid(row=1, column=1, sticky=tk.EW, padx=5, pady=2)
        ttk.Label(cred_frame, text="Enable Pwd:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(cred_frame, textvariable=self.enable_password_var, show="*", width=30).grid(row=2, column=1, sticky=tk.EW, padx=5, pady=2)
        cred_frame.columnconfigure(1, weight=1)

        # IP Addresses
        ip_frame = ttk.LabelFrame(config_frame, text="Target Devices", padding=10)
        ip_frame.pack(fill=tk.X, pady=5)
        ttk.Label(ip_frame, text="IPs/Ranges (e.g., 10.0.0.1; 192.168.1.5-10):").pack(anchor=tk.W, padx=5)
        ttk.Entry(ip_frame, textvariable=self.ip_range_var).pack(fill=tk.X, padx=5, pady=5)

        # Commands
        cmd_frame = ttk.LabelFrame(config_frame, text="Commands to Send", padding=10)
        cmd_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.command_text = scrolledtext.ScrolledText(cmd_frame, height=10, width=50, wrap=tk.WORD)
        self.command_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.command_text.insert(tk.END, "show version\nshow ip interface brief\n") # Example commands

        # Buttons
        btn_frame = ttk.Frame(config_frame, padding=(0, 10))
        btn_frame.pack(fill=tk.X)
        self.connect_btn = ttk.Button(btn_frame, text="Connect", command=self.start_connections)
        self.connect_btn.pack(side=tk.LEFT, padx=5)
        self.send_btn = ttk.Button(btn_frame, text="Send Commands", command=self.send_commands, state=tk.DISABLED)
        self.send_btn.pack(side=tk.LEFT, padx=5)
        self.cancel_btn = ttk.Button(btn_frame, text="Cancel", command=self.cancel_operations, state=tk.DISABLED)
        self.cancel_btn.pack(side=tk.LEFT, padx=5)
        self.clear_btn = ttk.Button(btn_frame, text="Clear Logs", command=self.clear_logs)
        self.clear_btn.pack(side=tk.RIGHT, padx=5)


        # Right Side (Device Status Treeview)
        status_frame = ttk.LabelFrame(top_paned_window, text="Device Status", padding=10)
        top_paned_window.add(status_frame)

        columns = ('ip', 'status', 'message')
        self.device_tree = ttk.Treeview(status_frame, columns=columns, show='headings', height=15)
        self.device_tree.pack(fill=tk.BOTH, expand=True)

        self.device_tree.heading('ip', text='IP Address')
        self.device_tree.column('ip', width=120, anchor=tk.W)
        self.device_tree.heading('status', text='Status')
        self.device_tree.column('status', width=100, anchor=tk.W)
        self.device_tree.heading('message', text='Details')
        self.device_tree.column('message', width=300, anchor=tk.W)

        # Treeview scrollbar
        tree_scrollbar = ttk.Scrollbar(status_frame, orient=tk.VERTICAL, command=self.device_tree.yview)
        tree_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.device_tree.configure(yscrollcommand=tree_scrollbar.set)

        # --- Bottom Pane --- (Logs and Individual Consoles)
        bottom_frame = ttk.Frame(main_paned_window, padding=5)
        main_paned_window.add(bottom_frame)

        bottom_notebook = ttk.Notebook(bottom_frame)
        bottom_notebook.pack(fill=tk.BOTH, expand=True)
        

        # General Log Tab
        log_frame = ttk.Frame(bottom_notebook, padding=5)
        bottom_notebook.add(log_frame, text="General Log")
        ttk.Label(log_frame, text="Application Log:", style='Title.TLabel').pack(anchor=tk.W, pady=(0, 5))
        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, width=100, wrap=tk.WORD, state=tk.DISABLED)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # Individual Device Console Tab Area
        self.console_notebook_frame = ttk.Frame(bottom_notebook, padding=5)
        bottom_notebook.add(self.console_notebook_frame, text="Device Consoles")
        ttk.Label(self.console_notebook_frame, text="Individual Device Output:", style='Title.TLabel').pack(anchor=tk.W, pady=(0, 5))
        self.console_notebook = ttk.Notebook(self.console_notebook_frame)
        self.console_notebook.pack(fill=tk.BOTH, expand=True)
        self.console_tabs: Dict[str, scrolledtext.ScrolledText] = {} # IP -> ScrolledText widget


        # Status Bar
        self.status_bar = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W, style='Status.TLabel')
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)


    def update_status_bar(self, text: Optional[str] = None):
        if text:
            self.status_bar.config(text=text)
        else:
            # Default status update
            conn_count = len([d for d in self.device_manager.devices.values() if d.status == STATUS_CONNECTED])
            fail_count = len([d for d in self.device_manager.devices.values() if d.status in [STATUS_FAILED, STATUS_ERROR]])
            pend_count = len([d for d in self.device_manager.devices.values() if d.status == STATUS_PENDING])
            busy_count = len([d for d in self.device_manager.devices.values() if d.status in [STATUS_CONNECTING, STATUS_EXECUTING]])

            status_text = f"Ready | Devices: {len(self.device_manager.devices)} | Connected: {conn_count} | Failed/Error: {fail_count} | Pending: {pend_count} | Busy: {busy_count}"
            if self.device_manager.is_connecting:
                status_text += " | Status: Connecting..."
            elif self.device_manager.is_sending_commands:
                status_text += " | Status: Sending Commands..."
            self.status_bar.config(text=status_text)

    def log_message(self, msg: str, level: str = "INFO"):
        """Appends a message to the General Log text area."""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_msg = f"[{now}] [{level}] {msg}\n"
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, formatted_msg)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def clear_logs(self):
        """Clears the General Log and individual console tabs."""
        self.log_text.config(state=tk.NORMAL)
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state=tk.DISABLED)
        # Clear console tabs
        for ip, text_widget in self.console_tabs.items():
             text_widget.config(state=tk.NORMAL)
             text_widget.delete(1.0, tk.END)
             text_widget.config(state=tk.DISABLED)
        self.log_message("Logs cleared.")


    def update_device_tree(self, device: NetworkDevice):
        """Adds or updates a device in the Treeview."""
        if device.treeview_item_id:
            try:
                self.device_tree.item(device.treeview_item_id, values=(
                    device.ip,
                    device.status,
                    device.message[:100] + ('...' if len(device.message) > 100 else '') # Truncate long messages
                ))
                # Optional: Add tags for coloring based on status
                self.device_tree.tag_configure(STATUS_CONNECTED, foreground='green')
                self.device_tree.tag_configure(STATUS_FAILED, foreground='red')
                self.device_tree.tag_configure(STATUS_ERROR, foreground='red', font=('TkDefaultFont', 9, 'bold'))
                self.device_tree.tag_configure(STATUS_CONNECTING, foreground='blue')
                self.device_tree.tag_configure(STATUS_EXECUTING, foreground='orange')

                # Apply the tag
                tags_to_apply = ()
                if device.status in [STATUS_CONNECTED, STATUS_FAILED, STATUS_ERROR, STATUS_CONNECTING, STATUS_EXECUTING]:
                   tags_to_apply = (device.status,)
                self.device_tree.item(device.treeview_item_id, tags=tags_to_apply)

            except tk.TclError:
                 print(f"Warning: Could not update Treeview item for {device.ip} (item might no longer exist).")
                 device.treeview_item_id = None # Reset ID if invalid
                 # Optionally re-add if needed, but might cause duplicates if not handled carefully
        else:
            # Insert new item
             device.treeview_item_id = self.device_tree.insert('', tk.END, values=(
                 device.ip,
                 device.status,
                 device.message[:100] + ('...' if len(device.message) > 100 else '')
             ))


    def add_console_tab(self, device: NetworkDevice):
        """Adds a new tab for a device's console output."""
        ip = device.ip
        if ip in self.console_tabs:
            return # Tab already exists

        tab_frame = ttk.Frame(self.console_notebook, padding=2)
        console_output_text = scrolledtext.ScrolledText(tab_frame, wrap=tk.WORD, height=10, state=tk.DISABLED)
        console_output_text.pack(fill=tk.BOTH, expand=True)

        self.console_tabs[ip] = console_output_text
        self.console_notebook.add(tab_frame, text=ip)

        # Add initial buffered output if any exists from connection phase
        if device.output_buffer:
            console_output_text.config(state=tk.NORMAL)
            console_output_text.insert(tk.END, device.output_buffer)
            console_output_text.see(tk.END)
            console_output_text.config(state=tk.DISABLED)


    def update_console_output(self, ip: str, output: str):
        """Appends output to the specific device's console tab."""
        if ip in self.console_tabs:
            text_widget = self.console_tabs[ip]
            text_widget.config(state=tk.NORMAL)
            text_widget.insert(tk.END, output)
            text_widget.see(tk.END) # Auto-scroll
            text_widget.config(state=tk.DISABLED)
        else:
            # Should not happen if tabs are created on successful connection
            self.log_message(f"Received output for unknown console tab: {ip}", "WARN")


    def clear_device_tree_and_consoles(self):
        """Clears the Treeview and removes all console tabs."""
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        # Remove tabs from notebook
        for tab_id in self.console_notebook.tabs():
            self.console_notebook.forget(tab_id)
        self.console_tabs.clear()


    def update_button_states(self):
        """Enable/disable buttons based on application state."""
        is_connecting = self.device_manager.is_connecting
        is_sending = self.device_manager.is_sending_commands
        is_busy = is_connecting or is_sending
        has_connected_devices = any(d.status == STATUS_CONNECTED for d in self.device_manager.devices.values())

        self.connect_btn.config(state=tk.DISABLED if is_busy else tk.NORMAL)
        self.send_btn.config(state=tk.NORMAL if has_connected_devices and not is_busy else tk.DISABLED)
        self.cancel_btn.config(state=tk.NORMAL if is_busy else tk.DISABLED)
        self.clear_btn.config(state=tk.NORMAL if not is_busy else tk.DISABLED) # Allow clearing logs unless busy


    def check_queues(self):
        """Periodically check status and output queues for updates from worker threads."""
        try:
            while True: # Process all messages currently in queue
                msg_type, data = self.status_queue.get_nowait()

                if msg_type == "log_info":
                    self.log_message(data, "INFO")
                elif msg_type == "log_warn":
                    self.log_message(data, "WARN")
                elif msg_type == "log_error":
                    self.log_message(data, "ERROR")
                elif msg_type == "update_device":
                    self.update_device_tree(data) # data is the NetworkDevice object
                elif msg_type == "add_device":
                     self.update_device_tree(data) # Add to treeview initially
                elif msg_type == "add_console_tab":
                    self.add_console_tab(data) # data is NetworkDevice
                elif msg_type == "clear_devices":
                    self.clear_device_tree_and_consoles()
                elif msg_type in ["connection_start", "connection_end", "command_start", "command_end"]:
                    # These just trigger UI state updates
                    pass
                else:
                     self.log_message(f"Unknown status queue message type: {msg_type}", "ERROR")

                self.status_queue.task_done()

        except queue.Empty:
            pass # No status messages

        try:
            while True: # Process all output messages
                ip, output = self.output_queue.get_nowait()
                self.update_console_output(ip, output)
                self.output_queue.task_done()
        except queue.Empty:
            pass # No output messages


        # Update buttons and status bar after processing queues
        self.update_button_states()
        self.update_status_bar()

        # Schedule next check
        self.root.after(150, self.check_queues) # Check every 150ms

    # --- Actions ---

    def start_connections(self):
        """Validates input and starts the connection process."""
        username = self.username_var.get()
        password = self.password_var.get()
        enable_password = self.enable_password_var.get() # Optional
        ip_range_str = self.ip_range_var.get()

        if not username or not password:
            messagebox.showerror("Input Error", "Username and Password are required.")
            return
        if not ip_range_str:
            messagebox.showerror("Input Error", "IP Address(es)/Range(s) are required.")
            return

        ip_addresses = self.device_manager.parse_ip_range(ip_range_str)
        if not ip_addresses:
            messagebox.showerror("Input Error", "Invalid IP address or range format. Check logs for details.")
            return

        creds = {
            "username": username,
            "password": password,
            "enable_password": enable_password,
        }

        self.log_message(f"Attempting connections to {len(ip_addresses)} devices...", "INFO")
        self.device_manager.start_connections(ip_addresses, creds)
        self.update_button_states() # Disable buttons immediately

    def send_commands(self):
        """Gets commands from the text area and tells DeviceManager to send them."""
        commands = self.command_text.get(1.0, tk.END).strip().split('\n')
        commands = [cmd.strip() for cmd in commands if cmd.strip()] # Clean list

        if not commands:
             messagebox.showwarning("Input Error", "No commands entered to send.")
             return

        self.log_message(f"Sending {len(commands)} commands to connected devices...", "INFO")
        self.device_manager.send_commands(commands)
        self.update_button_states() # Disable buttons immediately

    def cancel_operations(self):
        """Tells the DeviceManager to signal cancellation."""
        self.device_manager.cancel_operations()
        # Button state will update in the next check_queues cycle

    def on_close(self):
        """Handle application closing: cleanup connections."""
        if messagebox.askokcancel("Quit", "Do you want to quit? Active connections will be closed."):
            self.device_manager.cleanup()
            # Give cleanup a moment
            self.root.after(200, self.root.destroy)


# --- Main Execution ---
if __name__ == "__main__":
    import socket # Make sure socket is imported if used in exceptions

    root = tk.Tk()
    app = NetworkConfigApp(root)
    root.mainloop()