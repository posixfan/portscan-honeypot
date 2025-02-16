# Portscan Honeypot

A simple TCP honeypot designed to detect and log port scanning activities. This honeypot listens on a specified network interface, captures TCP SYN packets, and identifies potential port scanning attempts. It can send email and Telegram notifications when suspicious activity is detected.

## Features

- **Port Scanning Detection**: Detects when an IP address scans more than 2 different ports.
- **Logging**: Logs detected activities to a file (`honeypot.log`) if enabled.
- **Email Notifications**: Sends email alerts when port scanning is detected (optional).
- **Telegram Notifications**: Sends Telegram messages when port scanning is detected (optional).
- **Root Privileges**: Requires root privileges to run, ensuring it can capture packets on the specified interface.

## Prerequisites

- Python 3.x
- `scapy` library (`pip install scapy`)
- `requests` library (`pip install requests`)
- Root privileges (required for packet capture)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/posixfan/portscan-honeypot
   cd portscan-honeypot.py
   ```
2. Install the required Python libraries:
   ```bash
   pip install -r requirements.txt
   ```
## Usage
Run the honeypot with the following command:
```bash
sudo python3 portscan-honeypot.py <interface> [--logging] [--email] [--telegram]
```
### Arguments
<interface>: The network interface to listen on (e.g., `eth0`).
- `--logging`: Enable logging to `honeypot.log`.
- `--email`: Enable email notifications.
- `--telegram`: Enable Telegram notifications.
### Example
```bash
sudo python3 portscan-honeypot.py eth0 --logging --email
```
This command will start the honeypot on the `eth0` interface, enable logging, and send email notifications when port scanning is detected.
## Configuration
### Email Notifications
To enable email notifications, modify the send_email function with your SMTP server details, login credentials, and recipient email address.
```python3
def send_email(line):
    try:
        login = 'honeypot@example.com'  # Replace with your email
        server = smtp.SMTP('mx.mycorp.com', 25)  # Replace with your SMTP server
        subject = 'Port scanning detected'
        email = 'iss@example.com'  # Replace with the recipient email
        text = line

        mime = MIMEText(text, 'plain', 'utf-8')
        mime['Subject'] = Header(subject, 'utf-8')

        server.sendmail(login, email, mime.as_string())
    except Exception as error:
        print(f'\033[31m[!]\033[0m Error sending an email: {error}')
```
### Telegram Notifications
To enable Telegram notifications, set your bot's API token and chat ID in the send_telegram function.
```python3
def send_telegram(line):
    api_token = 'YOUR_TELEGRAM_BOT_API_TOKEN'  # Replace with your bot's API token
    hook_url = f'https://api.telegram.org/bot{api_token}/sendMessage'
    CHAT_ID = 'YOUR_CHAT_ID'  # Replace with your chat ID
    msg_data = {}
    msg_data['chat_id'] = CHAT_ID
    msg_data['text'] = line
    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}

    post(hook_url, headers=headers, data=json.dumps(msg_data, ensure_ascii=False))
```
### Logging
If logging is enabled, the honeypot will write detected activities to honeypot.log in the following format:
```bash
[<detection_time>] Port scanning detected from <ip>. Ports scanned: <ports>
```
### Contributing
Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

### Disclaimer
This honeypot is intended for educational and research purposes only. Use it responsibly and ensure you have permission to monitor the network interface you are using.

### Author
Andrew Razuvaev - [GitHub](https://github.com/posixfan) | <posixfan87@yandex.ru>
