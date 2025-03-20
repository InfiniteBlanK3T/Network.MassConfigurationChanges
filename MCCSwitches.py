import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import paramiko
import threading
import re
import ipaddress
import queue
from typing import List, Set, Dict
from time import sleep
from datetime import datetime

class NetworkDevice:
    def __init__(self, ip: str):
        self.ip = ip
        self.status = "Pending"
        self.connection = None
        self.error = None
        self.output_buffer = ""

class NetworkConfigTool:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Network Configuration Tool")
        self.root.geometry("1000x800")  # Increased window size
        
        # Style configuration
        self.style = ttk.Style()
        self.style.configure('TButton', padding=5)
        self.style.configure('TLabel', padding=5)
        self.style.configure('TEntry', padding=5)
        
        self.devices: Dict[str, NetworkDevice] = {}
        self.connection_queue = queue.Queue()
        self.status_queue = queue.Queue()
        self.is_connecting = False
        
        self.create_gui()
        
        # Start the status update checker
        self.check_status_queue()
        
    def create_gui(self):
        # Create main container with weights
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        # Credentials Frame
        cred_frame = ttk.LabelFrame(main_frame, text="Credentials", padding="5")
        cred_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(cred_frame, text="Username:").grid(row=0, column=0, sticky=tk.W)
        self.username_var = tk.StringVar()
        ttk.Entry(cred_frame, textvariable=self.username_var).grid(row=0, column=1, sticky=(tk.W, tk.E))
        
        ttk.Label(cred_frame, text="Password:").grid(row=1, column=0, sticky=tk.W)
        self.password_var = tk.StringVar()
        ttk.Entry(cred_frame, textvariable=self.password_var, show="*").grid(row=1, column=1, sticky=(tk.W, tk.E))
        
        ttk.Label(cred_frame, text="Enable Password:").grid(row=2, column=0, sticky=tk.W)
        self.enable_password_var = tk.StringVar()
        ttk.Entry(cred_frame, textvariable=self.enable_password_var, show="*").grid(row=2, column=1, sticky=(tk.W, tk.E))
        
        # IP Range Frame
        ip_frame = ttk.LabelFrame(main_frame, text="IP Addresses", padding="5")
        ip_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        ttk.Label(ip_frame, text="IP Range (e.g., 192.168.0.1-30;192.168.0.35):").grid(row=0, column=0, sticky=tk.W)
        self.ip_range_var = tk.StringVar()
        ttk.Entry(ip_frame, textvariable=self.ip_range_var).grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Create notebook for status and command
        notebook = ttk.Notebook(main_frame)
        notebook.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        main_frame.grid_rowconfigure(2, weight=1)
        
        # Status Frame in Notebook
        status_frame = ttk.Frame(notebook, padding="5")
        notebook.add(status_frame, text="Connection Status")
        
        # Connection summary frame
        self.summary_text = scrolledtext.ScrolledText(status_frame, height=5, width=80)
        self.summary_text.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=5)
        
        # Device status tree
        columns = ('IP', 'Status', 'Last Update')
        self.device_tree = ttk.Treeview(status_frame, columns=columns, show='headings', height=10)
        
        # Configure columns
        for col in columns:
            self.device_tree.heading(col, text=col)
            self.device_tree.column(col, width=150)
        
        self.device_tree.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # Detailed output for selected device
        ttk.Label(status_frame, text="Selected Device Output:").grid(row=2, column=0, sticky=tk.W)
        self.detail_text = scrolledtext.ScrolledText(status_frame, height=10, width=80)
        self.detail_text.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Bind selection event
        self.device_tree.bind('<<TreeviewSelect>>', self.on_device_select)
        
        # Command Frame in Notebook
        cmd_frame = ttk.Frame(notebook, padding="5")
        notebook.add(cmd_frame, text="Commands")
        
        ttk.Label(cmd_frame, text="Enter commands (one per line):").grid(row=0, column=0, sticky=tk.W)
        self.command_text = scrolledtext.ScrolledText(cmd_frame, height=10, width=80)
        self.command_text.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Command output
        ttk.Label(cmd_frame, text="Command Output:").grid(row=2, column=0, sticky=tk.W)
        self.command_output = scrolledtext.ScrolledText(cmd_frame, height=35, width=80)
        self.command_output.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Buttons Frame
        btn_frame = ttk.Frame(main_frame, padding="5")
        btn_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
        self.connect_btn = ttk.Button(btn_frame, text="Connect", command=self.start_connections)
        self.connect_btn.grid(row=0, column=0, padx=5)
        
        self.send_btn = ttk.Button(btn_frame, text="Send Commands", command=self.send_commands)
        self.send_btn.grid(row=0, column=1, padx=5)
        
        self.clear_btn = ttk.Button(btn_frame, text="Clear", command=self.clear_all)
        self.clear_btn.grid(row=0, column=2, padx=5)
        
    def parse_ip_range(self, ip_range: str) -> Set[str]:
        ip_set = set()
        ranges = ip_range.split(';')
        
        for r in ranges:
            r = r.strip()
            if '-' in r:
                try:
                    start_ip, end = r.rsplit('-', 1)
                    if '.' not in end:  # If end is just a number
                        base_ip = start_ip.rsplit('.', 1)[0]
                        start_num = int(start_ip.split('.')[-1])
                        end_num = int(end)
                        for i in range(start_num, end_num + 1):
                            ip = f"{base_ip}.{i}"
                            ip_set.add(ip)
                    else:  # If end is a full IP
                        start = int(ipaddress.ip_address(start_ip))
                        end = int(ipaddress.ip_address(end))
                        for i in range(start, end + 1):
                            ip = str(ipaddress.ip_address(i))
                            ip_set.add(ip)
                except ValueError as e:
                    messagebox.showerror("Error", f"Invalid IP range format in: {r}\nError: {str(e)}")
                    return set()
            else:
                try:
                    ipaddress.ip_address(r)
                    ip_set.add(r)
                except ValueError:
                    messagebox.showerror("Error", f"Invalid IP address: {r}")
                    return set()
        
        return ip_set
    
    def connect_device(self, device: NetworkDevice):
        try:
            self.status_queue.put(("summary", f"Attempting to connect to {device.ip}..."))
            self.update_device_status(device.ip, "Connecting", "Initiating connection...")
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                device.ip,
                username=self.username_var.get(),
                password=self.password_var.get(),
                timeout=10
            )
            
            # Get shell
            shell = ssh.invoke_shell()
            shell.send("enable\n")
            sleep(1)  # Wait for enable prompt
            output = shell.recv(1000).decode('utf-8')
            device.output_buffer += output
            
            shell.send(f"{self.enable_password_var.get()}\n")
            sleep(1)  # Wait for enable password processing
            output = shell.recv(1000).decode('utf-8')
            device.output_buffer += output
            
            device.connection = shell
            device.status = "Connected"
            self.status_queue.put(("summary", f"Successfully connected to {device.ip}"))
            self.update_device_status(device.ip, "Connected", "Ready for commands")
            
        except Exception as e:
            device.status = "Failed"
            device.error = str(e)
            self.status_queue.put(("summary", f"Failed to connect to {device.ip}: {str(e)}"))
            self.update_device_status(device.ip, "Failed", str(e))
        
        finally:
            self.connection_queue.put(device)
    
    def update_device_status(self, ip: str, status: str, message: str):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.status_queue.put(("device_update", (ip, status, message, timestamp)))
    
    def on_device_select(self, event):
        selected_items = self.device_tree.selection()
        if not selected_items:
            return
        
        ip = self.device_tree.item(selected_items[0])['values'][0]
        if ip in self.devices:
            device = self.devices[ip]
            self.detail_text.delete(1.0, tk.END)
            self.detail_text.insert(tk.END, device.output_buffer)
    
    def connection_manager(self):
        try:
            total_devices = len(self.devices)
            completed_devices = 0
            
            # Create and start connection threads
            threads = []
            for device in self.devices.values():
                thread = threading.Thread(target=self.connect_device, args=(device,))
                thread.daemon = True
                threads.append(thread)
                thread.start()
            
            # Wait for all connections to complete
            while completed_devices < total_devices:
                try:
                    device = self.connection_queue.get(timeout=1)
                    completed_devices += 1
                except queue.Empty:
                    continue
            
            self.status_queue.put(("summary", "\nConnection Summary:"))
            connected = sum(1 for d in self.devices.values() if d.status == "Connected")
            failed = sum(1 for d in self.devices.values() if d.status == "Failed")
            self.status_queue.put(("summary", f"Connected: {connected}, Failed: {failed}"))
            
        finally:
            self.is_connecting = False
            self.root.after(100, self.enable_buttons)
    
    def start_connections(self):
        if not all([self.username_var.get(), self.password_var.get(), self.enable_password_var.get(), self.ip_range_var.get()]):
            messagebox.showerror("Error", "Please fill in all credentials and IP range fields")
            return
        
        ip_addresses = self.parse_ip_range(self.ip_range_var.get())
        if not ip_addresses:
            return
        
        # Clear previous devices and status
        self.devices.clear()
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        self.summary_text.delete(1.0, tk.END)
        self.detail_text.delete(1.0, tk.END)
        self.command_output.delete(1.0, tk.END)
        
        # Initialize devices
        for ip in ip_addresses:
            self.devices[ip] = NetworkDevice(ip)
            self.device_tree.insert('', tk.END, values=(ip, "Pending", "Waiting to connect..."))
        
        self.status_queue.put(("summary", "Starting connections..."))
        
        # Disable buttons during connection
        self.is_connecting = True
        self.disable_buttons()
        
        # Start connection manager in a separate thread
        threading.Thread(target=self.connection_manager, daemon=True).start()
    
    def check_status_queue(self):
        """Check for status updates and update the GUI"""
        try:
            while True:
                message_type, message = self.status_queue.get_nowait()
                if message_type == "summary":
                    self.update_summary(message)
                elif message_type == "device_update":
                    self.update_tree(*message)
                elif message_type == "command":
                    self.update_command_output(message)
        except queue.Empty:
            pass
        finally:
            # Schedule the next check
            self.root.after(100, self.check_status_queue)
    
    def update_summary(self, message: str):
        self.summary_text.insert(tk.END, f"{message}\n")
        self.summary_text.see(tk.END)
    
    def update_tree(self, ip: str, status: str, message: str, timestamp: str):
        for item in self.device_tree.get_children():
            if self.device_tree.item(item)['values'][0] == ip:
                self.device_tree.item(item, values=(ip, status, f"{timestamp}: {message}"))
                break
    
    def update_command_output(self, message: str):
        self.command_output.insert(tk.END, f"{message}\n")
        self.command_output.see(tk.END)

    def disable_buttons(self):
        """Disable buttons during connection"""
        self.connect_btn.config(state='disabled')
        self.send_btn.config(state='disabled')
        self.clear_btn.config(state='disabled')
    
    def enable_buttons(self):
        """Enable buttons after connection attempts complete"""
        self.connect_btn.config(state='normal')
        self.send_btn.config(state='normal')
        self.clear_btn.config(state='normal')
    
    def send_commands(self):
        if not self.devices:
            messagebox.showerror("Error", "Please connect to devices first")
            return
        
        commands = self.command_text.get(1.0, tk.END).strip().split('\n')
        if not commands:
            messagebox.showerror("Error", "Please enter commands to send")
            return
        
        self.command_output.delete(1.0, tk.END)
        self.status_queue.put(("command", "\nSending commands to all connected devices..."))
        
        for device in self.devices.values():
            if device.status == "Connected":
                try:
                    self.status_queue.put(("command", f"\n=== Device {device.ip} ==="))
                    for cmd in commands:
                        self.status_queue.put(("command", f"\nSending command: {cmd}"))
                        device.connection.send(f"{cmd}\n")
                        sleep(1)  # Wait for command to complete
                        output = device.connection.recv(4096).decode('utf-8')
                        device.output_buffer += output
                        self.status_queue.put(("command", output))
                        self.update_device_status(device.ip, "Connected", f"Executed: {cmd}")
                except Exception as e:
                    error_msg = f"Error sending commands to {device.ip}: {str(e)}"
                    self.status_queue.put(("command", f"\nERROR: {error_msg}"))
                    self.update_device_status(device.ip, "Error", error_msg)
    
    def clear_all(self):
        self.status_text.delete(1.0, tk.END)
        self.command_text.delete(1.0, tk.END)
        self.command_output.delete(1.0, tk.END)
        self.detail_text.delete(1.0, tk.END)
        self.summary_text.delete(1.0, tk.END)
        self.ip_range_var.set("")
        self.devices.clear()
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
    
    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    app = NetworkConfigTool()
    app.run()