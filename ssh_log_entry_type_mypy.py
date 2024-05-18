from abc import ABC, abstractmethod
import re
from datetime import datetime
from typing import Optional, Dict, Any

def convert_str_to_datetime(date_str: str) -> datetime:
    # Assuming the date format in the log is 'Dec 10 09:32:20'
    return datetime.strptime(date_str, '%b %d %H:%M:%S')

def get_user_from_log(log_dict: Dict[str, Any]) -> Optional[str]:
    # Placeholder implementation, replace with actual logic
    return log_dict.get('user')

def get_ipv4s_from_log(log_dict: Dict[str, Any]) -> Optional[str]:
    # Placeholder implementation, replace with actual logic
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    message = log_dict.get('message', '')
    ip_matches = re.findall(ip_pattern, message)
    return ip_matches[0] if ip_matches else None

class SSHLogEntry(ABC):
    def __init__(self, timestamp: datetime, message: str, pid: Optional[int] = None, hostname: Optional[str] = None):
        self._raw_message: str = message
        self.timestamp: datetime = timestamp
        self.pid: Optional[int] = pid
        self.hostname: Optional[str] = hostname

    @property
    def has_ip(self) -> bool:
        return bool(self.extract_ipv4_address(self._raw_message))

    @abstractmethod
    def validate(self) -> bool:
        pass

    @staticmethod
    def extract_ipv4_address(message: str) -> bool:
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        ip_matches = re.findall(ip_pattern, message)
        return bool(ip_matches)

    @abstractmethod
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(timestamp={self.timestamp}, message={self._raw_message}, pid={self.pid}, hostname={self.hostname})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SSHLogEntry):
            return (self.timestamp == other.timestamp and
                    self._raw_message == other._raw_message and
                    self.pid == self.pid and
                    self.hostname == self.hostname)
        return NotImplemented

    def __lt__(self, other: object) -> bool:
        if isinstance(other, SSHLogEntry):
            return self.timestamp < other.timestamp
        return NotImplemented

    def __gt__(self, other: object) -> bool:
        if isinstance(other, SSHLogEntry):
            return self.timestamp > other.timestamp
        return NotImplemented

class OdrzucenieHasla(SSHLogEntry):
    def __init__(self, timestamp: datetime, message: str, pid: Optional[int] = None, hostname: Optional[str] = None, user: Optional[str] = None, ip_address: Optional[str] = None):
        super().__init__(timestamp, message, pid, hostname)
        self.user: Optional[str] = user
        self.ip_address: Optional[str] = ip_address

    def validate(self) -> bool:
        return "Failed password" in self._raw_message

    @classmethod
    def from_dict(cls, dict: Dict[str, Any]) -> 'OdrzucenieHasla':
        date_str = dict.get("date")
        if date_str is None:
            raise ValueError("Missing date")
        message = dict.get("message")
        if message is None:
            raise ValueError("Missing message")
        timestamp: datetime = convert_str_to_datetime(date_str)
        pid: Optional[int] = dict.get("PID")
        hostname: Optional[str] = dict.get("hostname")
        user: Optional[str] = get_user_from_log(dict)
        ip_address: Optional[str] = get_ipv4s_from_log(dict)
        return cls(timestamp, message, pid, hostname, user, ip_address)

    def __repr__(self) -> str:
        return (f"OdrzucenieHasla(timestamp={self.timestamp}, message={self._raw_message}, "
                f"pid={self.pid}, hostname={self.hostname}, user={self.user}, ip_address={self.ip_address})")

class AkceptacjaHasla(SSHLogEntry):
    def __init__(self, timestamp: datetime, message: str, pid: Optional[int] = None, hostname: Optional[str] = None, user: Optional[str] = None, ip_address: Optional[str] = None):
        super().__init__(timestamp, message, pid, hostname)
        self.user: Optional[str] = user
        self.ip_address: Optional[str] = ip_address

    def validate(self) -> bool:
        return "Accepted password" in self._raw_message

    @classmethod
    def from_dict(cls, dict: Dict[str, Any]) -> 'AkceptacjaHasla':
        date_str = dict.get("date")
        if date_str is None:
            raise ValueError("Missing date")
        message = dict.get("message")
        if message is None:
            raise ValueError("Missing message")
        timestamp: datetime = convert_str_to_datetime(date_str)
        pid: Optional[int] = dict.get("PID")
        hostname: Optional[str] = dict.get("hostname")
        user: Optional[str] = get_user_from_log(dict)
        ip_address: Optional[str] = get_ipv4s_from_log(dict)
        return cls(timestamp, message, pid, hostname, user, ip_address)

    def __repr__(self) -> str:
        return (f"AkceptacjaHasla(timestamp={self.timestamp}, message={self._raw_message}, "
                f"pid={self.pid}, hostname={self.hostname}, user={self.user}, ip_address={self.ip_address})")

class Blad(SSHLogEntry):
    def __init__(self, timestamp: datetime, message: str, pid: Optional[int] = None, hostname: Optional[str] = None, error_message: Optional[str] = None):
        super().__init__(timestamp, message, pid, hostname)
        self.error_message: Optional[str] = error_message

    def validate(self) -> bool:
        return "error" in self._raw_message.lower()

    @classmethod
    def from_dict(cls, dict: Dict[str, Any]) -> 'Blad':
        date_str = dict.get("date")
        if date_str is None:
            raise ValueError("Missing date")
        message = dict.get("message")
        if message is None:
            raise ValueError("Missing message")
        timestamp: datetime = convert_str_to_datetime(date_str)
        pid: Optional[int] = dict.get("PID")
        hostname: Optional[str] = dict.get("hostname")
        blad_message: Optional[str] = dict.get("message")
        return cls(timestamp, message, pid, hostname, blad_message)

    def __repr__(self) -> str:
        return (f"Blad(timestamp={self.timestamp}, message={self._raw_message}, "
                f"pid={self.pid}, hostname={self.hostname}, error_message={self.error_message})")

class Inne(SSHLogEntry):
    def __init__(self, timestamp: datetime, message: str, pid: Optional[int] = None, hostname: Optional[str] = None, error_message: Optional[str] = None):
        super().__init__(timestamp, message, pid, hostname)
        self.error_message: Optional[str] = error_message

    def validate(self) -> bool:
        return True

    @classmethod
    def from_dict(cls, dict: Dict[str, Any]) -> 'Inne':
        date_str = dict.get("date")
        if date_str is None:
            raise ValueError("Missing date")
        message = dict.get("message")
        if message is None:
            raise ValueError("Missing message")
        timestamp: datetime = convert_str_to_datetime(date_str)
        pid: Optional[int] = dict.get("PID")
        hostname: Optional[str] = dict.get("hostname")
        inne_message: Optional[str] = dict.get("message")
        return cls(timestamp, message, pid, hostname, inne_message)

    def __repr__(self) -> str:
        return (f"Inne(timestamp={self.timestamp}, message={self._raw_message}, "
                f"pid={self.pid}, hostname={self.hostname}, error_message={self.error_message})")
