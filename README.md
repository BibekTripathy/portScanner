# portScanner

A robust Command Line Interface (CLI) tool for scanning, mapping, and monitoring network ports.

## Features

- **Port Scanning:** Quickly identify listening ports on your system.
- **Process Mapping:** Map ports to their respective running processes and users.
- **Change Detection:** Compare current scans with previous logs to detect changes.
- **Monitoring:** Real-time monitoring capabilities (via `modules/monitor`).
- **Rich Interface:** User-friendly CLI output using the `rich` library.

## Installation

Install all required dependencies using pip:

```bash
pip install -r requirements.txt
```

## Usage

### Advanced CLI
Run the main script to start the interactive CLI with full features:

```bash
python portScanner.py
```

### Simple Mode
For a quick, lightweight scan, you can run:

```bash
python portScanner-simple.py
```

## Future Roadmap

- **App Interface:** I am actively planning to develop a Graphical User Interface (GUI) application in the future to provide an even more accessible experience for visualizing network activity.

## Version
1.0.0 (CLI Only)