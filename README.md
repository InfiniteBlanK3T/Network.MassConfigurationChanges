# Mass Network Configuration Tool (MCNTools)

A graphical tool built with Python and Tkinter to apply configuration commands simultaneously to multiple network devices (switches, routers) via SSH.

## Features

* Connect to multiple devices using a specified IP range or list.
* Uses SSH (Paramiko library) for secure connections.
* Supports username/password and enable password authentication.
* Send multiple configuration commands sequentially to all connected devices.
* Displays connection status and command output.
* Simple GUI for ease of use.

## Project Structure (Recommended)
```
    MassConfigurationChanges/
    ├── src/
    │   └── mcn_tools/
    │       ├── init.py
    │       ├── main.py
    │       └── network.py
    ├── docs/
    ├── tests/
    ├── .gitignore
    ├── LICENSE
    ├── README.md
    └── requirements.txt
```

## Installation & Setup

1.  **Clone the repository:**
    ```bash
    git clone <your-repository-url>
    cd MassConfigurationChanges
    ```
2.  **Create and activate a virtual environment (Recommended):**
    ```bash
    # Windows
    python -m venv venv
    venv\Scripts\activate

    # Linux/macOS
    python3 -m venv venv
    source venv/bin/activate
    ```
3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

## Usage

1.  **Ensure the virtual environment is active.**
2.  **Run the application:**
    ```bash
    python src/mcn_tools/main.py
    ```
    *(Adjust the command if your entry point script is named differently)*
3.  **Enter Credentials:** Fill in the Username, Password, and Enable Password fields.
4.  **Enter IP Addresses:** Provide individual IPs separated by semicolons (`;`) or ranges using a hyphen (`-`) within the last octet (e.g., `192.168.1.10; 192.168.1.20-25`).
5.  **Click "Connect":** The tool will attempt to connect to all specified devices. Status updates will appear in the "Connection Status" box.
6.  **Enter Commands:** Type the configuration commands you want to send into the "Commands" box, one command per line.
7.  **Click "Send Commands":** The commands will be sent to all successfully connected devices. Output will appear in the "Connection Status" box.
8.  **Click "Clear":** Clears the status box, command box, IP range field, and disconnects devices.

## Dependencies

* [Python](https://www.python.org/) 3.x
* [Paramiko](https://www.paramiko.org/): For SSH connectivity.
    *(See `requirements.txt` for specific version if applicable)*

## Contributing

*(Optional: Add guidelines if you want others to contribute. E.g., fork the repo, create a branch, submit a pull request.)*
