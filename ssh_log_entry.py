import re
from ipaddress import IPv4Address


class SSHLogEntry:
    def __init__(self, timestamp, message, pid=None, hostname=None):
        self.timestamp = timestamp
        self.hostname = hostname
        self.message = message
        self.pid = pid

    def __str__(self):
        entry_str = f"Timestamp: {self.timestamp}, Message: {self.message}"
        if self.pid:
            entry_str += f", PID: {self.pid}"
        if self.hostname:
            entry_str += f", Hostname: {self.hostname}"
        return entry_str

    def extract_ipv4_address(self):
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        ip_matches = re.findall(ip_pattern, self.message)
        if ip_matches:
            return IPv4Address(ip_matches[0])
        else:
            return None
