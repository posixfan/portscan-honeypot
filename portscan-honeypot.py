#!/usr/bin/env python3
# https://github.com/posixfan/portscan-honeypot
# Standard library imports
import argparse
from collections import defaultdict
from datetime import datetime
from email.header import Header
from email.mime.text import MIMEText
import json
import smtplib as smtp
import time
from os import getuid

# Third-party library imports
from requests import post
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

# Argument parser setup
parser = argparse.ArgumentParser(description='Multithreaded TCP/UDP scanner honeypot')
parser.add_argument('iface', type=str, help='The network interface to listen on.')
parser.add_argument('--logging', action='store_true',
                    help='Enable logging to a file (honeypot.log).')
parser.add_argument('--email', action='store_true',
                    help='Sending email notifications.')
parser.add_argument('--telegram', action='store_true',
                    help='Sending telegram notifications.')
parser.add_argument('--ignore', type=str, default='',
                    help='IP address to ignore during port scanning detection.')
args = parser.parse_args()

# Dictionary to store SYN packets information for each IP
ip_port_map = defaultdict(lambda: {'tcp': set(), 'udp': set()})

# Dictionary to store the first detection time for each IP
ip_detection_time = {}

# Start time of tracking
start_time = time.time()

# Last report generation time
last_report_time = time.time()

# Log file name
LOG_FILE = 'honeypot.log'

def is_running_as_root():
    """Check if the script is running with root privileges."""
    return getuid() == 0

def send_email(line):
    """Function for sending email alerts"""
    try:
        login = 'honeypot@example.com'
        server = smtp.SMTP('mx.mycorp.com', 25)
        subject = 'Port scanning detected'
        email = 'iss@example.com'
        text = line

        mime = MIMEText(text, 'plain', 'utf-8')
        mime['Subject'] = Header(subject, 'utf-8')

        server.sendmail(login, email, mime.as_string())
    except Exception as error:
        print(f'\033[31m[!]\033[0m Error sending an email: {error}')

def send_telegram(line):
    """Function for sending telegram alerts"""
    api_token = ''
    hook_url = f'https://api.telegram.org/bot{api_token}/sendMessage'
    CHAT_ID = ''
    msg_data = {}
    msg_data['chat_id'] = CHAT_ID
    msg_data['text'] = line
    headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}

    post(hook_url, headers=headers, data=json.dumps(msg_data, ensure_ascii=False))

def log_message(message):
    """Log a message to the console and optionally to a file."""
    print(f'\033[31m[!]\033[0m {message}')
    if args.logging:
        with open(LOG_FILE, 'a') as log_file:
            log_file.write(f'{message}\n')

def packet_callback(packet):
    """Callback function to process each captured packet."""
    global start_time, last_report_time

    # Check if the packet contains IP layer
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src

        # Skip if the IP is in the ignore list
        if src_ip == args.ignore:
            return

        # Check if the packet contains TCP layer
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)

            # Check if the SYN flag is set
            if tcp_layer.flags == 'S':
                dst_port = tcp_layer.dport

                # Add the port to the set for this IP
                ip_port_map[src_ip]['tcp'].add(dst_port)

                # Reset data if more than 2 seconds have passed
                if time.time() - start_time > 2:
                    start_time = time.time()

                # If more than 2 different ports are scanned from the same IP
                if len(ip_port_map[src_ip]['tcp']) > 2:
                    # Record the first detection time if not already recorded
                    if src_ip not in ip_detection_time:
                        ip_detection_time[src_ip] = datetime.now().strftime('%d.%m.%Y %H:%M:%S')

        # Check if the packet contains UDP layer
        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            dst_port = udp_layer.dport

            # Add the port to the set for this IP
            ip_port_map[src_ip]['udp'].add(dst_port)

            # Reset data if more than 2 seconds have passed
            if time.time() - start_time > 2:
                start_time = time.time()

            # If more than 2 different ports are scanned from the same IP
            if len(ip_port_map[src_ip]['udp']) > 2:
                # Record the first detection time if not already recorded
                if src_ip not in ip_detection_time:
                    ip_detection_time[src_ip] = datetime.now().strftime('%d.%m.%Y %H:%M:%S')

    # Check if it's time to generate a report
    if time.time() - last_report_time >= 30:
        generate_report()
        last_report_time = time.time()

def generate_report():
    """Generate a summary report of detected port scanning activities."""
    # If no data, skip the report
    if not ip_port_map:
        return

    # Filter IPs with more than 2 ports scanned
    suspicious_ips = {ip: ports for ip, ports in ip_port_map.items() if len(ports['tcp']) > 2 or len(ports['udp']) > 2}
    if not suspicious_ips:
        return  # Skip if no suspicious activity is found

    for ip, ports in suspicious_ips.items():
        # Check TCP ports
        if len(ports['tcp']) > 2:
            scan_type = 'TCP'
            ports_set = ports['tcp']
        # Check UDP ports
        elif len(ports['udp']) > 2:
            scan_type = 'UDP'
            ports_set = ports['udp']
        else:
            continue

        # Format the list of ports
        if len(ports_set) <= 10:
            ports_str = ','.join(map(str, sorted(ports_set)))
        else:
            # If there are many ports, show a range
            min_port = min(ports_set)
            max_port = max(ports_set)
            ports_str = f'{min_port}-{max_port}'

        # Get the first detection time
        detection_time = ip_detection_time.get(ip, 'Unknown')
        log_message(f'[{detection_time}] {scan_type} port scanning detected from {ip}. '
                    f'Ports scanned: {ports_str}')

        if args.email:
            send_email(f'[{detection_time}] {scan_type} port scanning detected from {ip}. '
                       f'Ports scanned: {ports_str}')
        if args.telegram:
            send_telegram(f'[{detection_time}] {scan_type} port scanning detected from {ip}. '
                          f'Ports scanned: {ports_str}')

    # Clear data after generating the report
    ip_port_map.clear()
    ip_detection_time.clear()

def start_sniffing(interface):
    """Start sniffing on the specified network interface."""
    # This message is only for console output, not for logging
    print(f'\033[32m[+]\033[0m Listening on the {interface} interface...')
    sniff(iface=interface, prn=packet_callback, store=False)

def main():
    """Main function to start the honeypot."""
    if not is_running_as_root():
        # This message is only for console output, not for logging
        print('\033[31m[-]\033[0m Root privileges are required.')
        return

    network_interface = args.iface
    start_sniffing(network_interface)

if __name__ == '__main__':
    main()
