# CyberShield – Network Security & Device Connection System

A Flask-based educational project with a neon-green cybersecurity dashboard, virtual connection simulation, basic LAN checks, host-side messaging and small-file uploads.

## Requirements
- Windows 10/11 on both computers
- Python 3.10 or newer on Computer 1
- Both computers connected to the same reachable Wi-Fi network
- Only test devices and networks you own or have permission to assess

## Run on Computer 1 (host)
1. Extract the project folder.
2. Open the folder in VS Code.
3. Open Terminal → New Terminal.
4. Run `py -m venv .venv`
5. Run `.venv\\Scripts\\activate`
6. Run `pip install -r requirements.txt`
7. Run `python app.py`
8. Open `http://127.0.0.1:5000` on Computer 1.
9. Find Computer 1's local IPv4 address using the printed startup message or `ipconfig`.
10. If Windows Firewall asks, allow Python on your **Private** network only. Do not disable the firewall.

You can also double-click `run_windows.bat` to create the environment, install Flask and start the host.

## Open from Computer 2 (client)
1. Keep `app.py` running on Computer 1.
2. On Computer 2, open a browser and visit `http://HOST-IP:5000`, replacing `HOST-IP` with Computer 1's IPv4 address (for example `192.168.1.10`).
3. Both computers must be on the same Wi-Fi and the router must allow device-to-device traffic. Guest Wi-Fi or AP/client isolation may prevent this.
4. Use the page's message and file-transfer sections. Received files are stored in `uploads/` on Computer 1.

## Run the real LAN assessment
1. Keep Flask running on Computer 1 (the host).
2. On either computer, open the CyberShield page served by Computer 1. On Computer 2, use `http://HOST-IP:5000`.
3. In **Other laptop (Computer 2) IPv4 address**, type the other laptop's Wi-Fi IPv4 address from `ipconfig` (for example `192.168.1.17`). This field is editable.
4. Keep the host port set to `5000`, then click **Run LAN Security Check**.
5. The assessment validates the entered private IPv4 address, compares it with the host subnet, checks the host's local Flask port, and reads Windows Firewall status on the host. It does not require a second Flask server on Computer 2.

## Feature notes and honest limitations
- **Simulation:** the six virtual checks are demonstrations, not real scans.
- **IP validation:** validates the manually entered other-laptop IPv4 address. Automatic browser detection may prefill the field, but you can edit it or type another laptop address.
- **Port availability:** probes the host application port on the computer running Flask. This confirms the host service is listening; it does not prove the typed client IP is online. Actual client-to-host reachability is confirmed when Computer 2 opens the host page and can send a message.
- **Firewall:** on Windows, reads whether Windows Firewall profiles are enabled. It does not verify a specific Python inbound rule or change firewall settings.
- **Suspicious indicators:** checks a few unusual IP address ranges only. It is not antivirus, IDS, reputation lookup, or malware detection.
- **Network configuration:** performs a basic /24 comparison. Some networks use different subnet masks; treat this as a basic indicator, not definitive topology detection.
- **Timeout:** measures the host TCP probe with a 3-second timeout.
- **Warning decision:** the page lets the user acknowledge warnings. The app does not bypass OS firewall restrictions or force a failed TCP connection to succeed.
- **Transfer:** files are limited to 5 MB and stored on the host. This starter version is intended for a trusted private LAN demonstration, not public internet exposure. It does not provide end-to-end encryption or user authentication.

## Project structure

```text
CyberShield_Project/
├── app.py
├── requirements.txt
├── run_windows.bat
├── README.md
├── templates/
│   └── index.html
├── static/
│   ├── css/style.css
│   ├── js/app.js
│   └── images_reference.png
├── uploads/
└── logs/
```

## Stop the server
Press `Ctrl + C` in the terminal running Flask.


## Real LAN assessment: manual client IP entry

- The **Other laptop (Computer 2) IPv4 address** field is editable.
- Find the other laptop's address with `ipconfig` under its Wi-Fi adapter's IPv4 Address.
- Enter that address in CyberShield and run the check.
- The check validates the address and compares the /24 network. It checks the Flask host port locally and reads the host Windows Firewall state.
- To confirm the other laptop is actually connected, open `http://HOST-IP:5000` from that laptop and send a test message. A typed IP alone cannot prove that a device is online.
