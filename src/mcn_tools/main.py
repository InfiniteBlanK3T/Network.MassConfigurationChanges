import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import queue # Using queue is better for thread-safe GUI updates
from typing import List, Set, Dict, Any

# Import from our network module
from .network import NetworkDevice, parse_ip_range, connect_device, send_commands_to_device

class NetworkConfigTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Configuration Tool")
        self.root.geometry("800x600") # Adjusted size

        # Style configuration
        self.style = ttk.Style()
        # Use a theme that looks better across platforms if possible
        try:
            self.style.theme_use('clam') # Or 'alt', 'vista', 'xpnative'
        except tk.TclError:
            print("Clam theme not available, using default.")
        self.style.configure('TButton', padding=5)
        self.style.configure('TLabel', padding=5)
        self.style.configure('TEntry', padding=5)
        self.style.configure('TLabelframe.Label', padding=2)

        # Use a dictionary for easier device lookup by IP
        self.devices: Dict[str, NetworkDevice] = {}
        self.gui_queue = queue.Queue() # Queue for thread-safe GUI updates

        # Control flags
        self._is_connecting = False
        self._is_sending = False
        self._cancel_event = threading.Event() # To signal cancellation

        self.create_gui()
        self.check_gui_queue() # Start the queue checker

    def create_gui(self):
        # (GUI creation code remains largely the same as in MCNTools.py)
        # Create main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True) # Use pack or grid consistently

        # Credentials Frame
        cred_frame = ttk.LabelFrame(main_frame, text="Credentials", padding="10")
        cred_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(cred_frame, text="Username:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        self.username_var = tk.StringVar()
        ttk.Entry(cred_frame, textvariable=self.username_var, width=30).grid(row=0, column=1, sticky=tk.EW, padx=5, pady=2)

        ttk.Label(cred_frame, text="Password:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        self.password_var = tk.StringVar()
        ttk.Entry(cred_frame, textvariable=self.password_var, show="*", width=30).grid(row=1, column=1, sticky=tk.EW, padx=5, pady=2)

        ttk.Label(cred_frame, text="Enable Pwd:").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        self.enable_password_var = tk.StringVar()
        ttk.Entry(cred_frame, textvariable=self.enable_password_var, show="*", width=30).grid(row=2, column=1, sticky=tk.EW, padx=5, pady=2)
        cred_frame.columnconfigure(1, weight=1) # Make entry expand

        # IP Range Frame
        ip_frame = ttk.LabelFrame(main_frame, text="IP Addresses", padding="10")
        ip_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(ip_frame, text="IP Range/List (e.g., 192.168.0.1-10; 192.168.0.35):").pack(anchor=tk.W, padx=5)
        self.ip_range_var = tk.StringVar()
        ttk.Entry(ip_frame, textvariable=self.ip_range_var).pack(fill=tk.X, padx=5, pady=5)

        # Command Frame
        cmd_frame = ttk.LabelFrame(main_frame, text="Commands (one per line)", padding="10")
        cmd_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.command_text = scrolledtext.ScrolledText(cmd_frame, height=8, width=70, wrap=tk.WORD)
        self.command_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Status Frame - Placed below commands, above buttons
        status_frame = ttk.LabelFrame(main_frame, text="Status / Output Log", padding="10")
        status_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.status_text = scrolledtext.ScrolledText(status_frame, height=15, width=70, wrap=tk.WORD, state=tk.DISABLED)
        self.status_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        # Buttons Frame
        btn_frame = ttk.Frame(main_frame, padding="10")
        btn_frame.pack(fill=tk.X, padx=10, pady=(5, 10))

        self.connect_btn = ttk.Button(btn_frame, text="Connect", command=self.start_connections_thread)
        self.connect_btn.pack(side=tk.LEFT, padx=5)

        self.send_btn = ttk.Button(btn_frame, text="Send Commands", command=self.start_send_commands_thread, state=tk.DISABLED)
        self.send_btn.pack(side=tk.LEFT, padx=5)
        
        # Add Cancel button
        self.cancel_btn = ttk.Button(btn_frame, text="Cancel", command=self.cancel_operations, state=tk.DISABLED)
        self.cancel_btn.pack(side=tk.LEFT, padx=5)

        self.clear_btn = ttk.Button(btn_frame, text="Clear Log", command=self.clear_log)
        self.clear_btn.pack(side=tk.RIGHT, padx=5) # Move Clear to the right

    # --- Thread-safe GUI Update ---
    def queue_status_update(self, message: str):
        """Puts a status message onto the queue for the main thread to process."""
        self.gui_queue.put(message)

    def process_gui_queue(self):
        """Processes messages from the queue to update the GUI safely."""
        try:
            while True:
                message = self.gui_queue.get_nowait()
                self.update_status(message)
        except queue.Empty:
            pass # No messages in queue

    def check_gui_queue(self):
        """Periodically checks the queue and schedules the next check."""
        self.process_gui_queue()
        self.root.after(100, self.check_gui_queue) # Check every 100ms

    def update_status(self, message: str):
        """Updates the status text box in a thread-safe manner (called by process_gui_queue)."""
        self.status_text.config(state=tk.NORMAL)
        self.status_text.insert(tk.END, f"{message}\n")
        self.status_text.see(tk.END) # Auto-scroll
        self.status_text.config(state=tk.DISABLED)

    # --- Button State Management ---
    def update_button_states(self):
        """Enables/disables buttons based on current operation state."""
        is_busy = self._is_connecting or self._is_sending
        has_connections = any(d.status == "Connected" for d in self.devices.values())

        self.connect_btn.config(state=tk.DISABLED if is_busy else tk.NORMAL)
        # Enable Send only if not busy AND there are connected devices
        self.send_btn.config(state=tk.NORMAL if not is_busy and has_connections else tk.DISABLED)
        self.cancel_btn.config(state=tk.NORMAL if is_busy else tk.DISABLED)
        self.clear_btn.config(state=tk.NORMAL if not is_busy else tk.DISABLED)


    # --- Connection Logic ---
    def connections_worker(self, ip_addresses: Set[str], creds: Dict[str, Any]):
        """Worker function executed in a separate thread for connections."""
        self._is_connecting = True
        self._cancel_event.clear()
        self.queue_status_update("Starting connections...")
        # Update buttons via queue indirectly or directly if careful (direct here for simplicity)
        self.root.after(0, self.update_button_states)

        threads = []
        temp_devices: Dict[str, NetworkDevice] = {ip: NetworkDevice(ip) for ip in ip_addresses}
        
        # Atomically update the main devices dict (or wait until finished)
        # Here we'll update it after confirming connections
        
        for ip, device in temp_devices.items():
            if self._cancel_event.is_set():
                 self.queue_status_update(f"Connection process cancelled.")
                 break
                 
            thread = threading.Thread(
                target=connect_device,
                args=(device, creds, self.queue_status_update), # Pass device, creds, and callback
                daemon=True
            )
            threads.append(thread)
            thread.start()
            # Optional slight delay between starting threads if needed
            # time.sleep(0.05) 

        # Wait for all connection threads to complete or cancellation
        for thread in threads:
            while thread.is_alive():
                if self._cancel_event.is_set():
                     # Signal threads if possible (more complex) or just stop waiting
                     self.queue_status_update("Cancellation requested, waiting briefly...")
                     thread.join(timeout=0.5) # Give threads a moment to potentially exit
                     break
                thread.join(timeout=0.1) # Non-blocking wait


        # Update main device list only after attempts finish
        self.devices = temp_devices

        # Summary
        if not self._cancel_event.is_set():
            self.queue_status_update("\nConnection Summary:")
            connected = sum(1 for d in self.devices.values() if d.status == "Connected")
            failed = sum(1 for d in self.devices.values() if d.status == "Failed")
            self.queue_status_update(f"Connected: {connected}, Failed: {failed}")
        else:
            self.queue_status_update("\nConnection process cancelled.")


        self._is_connecting = False
        self._cancel_event.clear()
        # Update buttons once finished
        self.root.after(0, self.update_button_states)


    def start_connections_thread(self):
        """Starts the connection process in a background thread."""
        if self._is_connecting or self._is_sending:
             messagebox.showwarning("Busy", "Already performing an operation.")
             return

        username = self.username_var.get()
        password = self.password_var.get()
        enable_password = self.enable_password_var.get() # Can be empty
        ip_range_str = self.ip_range_var.get()

        if not username or not password: # Enable password is not strictly required
            messagebox.showerror("Input Error", "Username and Password are required.")
            return
        if not ip_range_str:
            messagebox.showerror("Input Error", "IP Address(es)/Range(s) are required.")
            return

        # Parse IPs using the function from the network module
        ip_addresses = parse_ip_range(ip_range_str)
        if not ip_addresses:
            # Error message already shown by parse_ip_range
            return

        creds = {
            "username": username,
            "password": password,
            "enable_password": enable_password,
        }

        # Clear previous status and device state before starting
        self.clear_log() # Clear the log area
        # Close existing connections if any before starting anew
        for device in self.devices.values():
            device.close_connection()
        self.devices.clear()

        # Start the worker thread
        conn_thread = threading.Thread(
            target=self.connections_worker,
            args=(ip_addresses, creds),
            daemon=True
        )
        conn_thread.start()
        # Update button states immediately
        self.update_button_states()


    # --- Command Sending Logic ---
    def send_commands_worker(self, commands: List[str]):
        """Worker function executed in a separate thread for sending commands."""
        self._is_sending = True
        self._cancel_event.clear()
        self.queue_status_update("\nSending commands...")
        self.root.after(0, self.update_button_states)

        # Create a list of devices to operate on to avoid issues if self.devices changes
        devices_to_command = [d for d in self.devices.values() if d.status == "Connected"]
        
        threads = []
        for device in devices_to_command:
            if self._cancel_event.is_set():
                 self.queue_status_update("Command sending cancelled.")
                 break

            thread = threading.Thread(
                 target=send_commands_to_device,
                 args=(device, commands, self.queue_status_update),
                 daemon=True
            )
            threads.append(thread)
            thread.start()
            # Stagger command sending slightly if needed
            # time.sleep(0.1)

        # Wait for command threads
        for thread in threads:
           while thread.is_alive():
                if self._cancel_event.is_set():
                     self.queue_status_update("Cancellation requested...")
                     thread.join(timeout=0.5)
                     break
                thread.join(timeout=0.1)


        if not self._cancel_event.is_set():
             self.queue_status_update("\nFinished sending commands.")
        else:
             self.queue_status_update("\nCommand sending process cancelled.")


        self._is_sending = False
        self._cancel_event.clear()
        self.root.after(0, self.update_button_states)


    def start_send_commands_thread(self):
        """Starts the command sending process in a background thread."""
        if self._is_connecting or self._is_sending:
             messagebox.showwarning("Busy", "Already performing an operation.")
             return

        commands = self.command_text.get(1.0, tk.END).strip().split('\n')
        commands = [cmd for cmd in commands if cmd.strip()] # Filter empty lines

        if not commands:
            messagebox.showerror("Input Error", "Please enter commands to send.")
            return

        connected_devices = [d for d in self.devices.values() if d.status == "Connected"]
        if not connected_devices:
             messagebox.showinfo("No Connections", "No devices are currently connected.")
             return

        # Start the worker thread
        cmd_thread = threading.Thread(
            target=self.send_commands_worker,
            args=(commands,),
            daemon=True
        )
        cmd_thread.start()
        self.update_button_states()


    # --- Cancellation and Cleanup ---
    def cancel_operations(self):
        """Signals any ongoing operation (connect/send) to cancel."""
        if self._is_connecting or self._is_sending:
            self.queue_status_update(">>> Cancellation requested <<<")
            self._cancel_event.set()
            # Buttons will update automatically on next state check or worker finish
        else:
             messagebox.showinfo("Idle", "No operation currently running to cancel.")

    def clear_log(self):
        """Clears the status/log text box."""
        self.status_text.config(state=tk.NORMAL)
        self.status_text.delete(1.0, tk.END)
        self.status_text.config(state=tk.DISABLED)

    def on_close(self):
        """Handles window closing: cleanup connections."""
        self.queue_status_update("Closing connections...")
        # Signal cancellation first
        self._cancel_event.set()
        
        # Give threads a moment to react
        self.root.update_idletasks()
        # time.sleep(0.2) # Optional brief pause
        
        # Explicitly close connections
        for device in self.devices.values():
            device.close_connection() # Ensure close is called
        
        self.queue_status_update("Exiting.")
        # Allow final GUI updates
        self.root.update_idletasks()
        # time.sleep(0.1)

        self.root.destroy()

# --- Main Execution ---
def main():
    root = tk.Tk()
    app = NetworkConfigTool(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close) # Handle closing cleanly
    root.mainloop()

if __name__ == "__main__":
    main()