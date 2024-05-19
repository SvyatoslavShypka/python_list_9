from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
import re

class SSHLogEntry(ABC):
    def __init__(self, timestamp: str, message: str, pid: int, hostname: str, ip_address: Optional[str] = None):
        self.timestamp = timestamp
        self.message = message
        self.pid = pid
        self.hostname = hostname
        self.ip_address = ip_address

    def validate_ip_address(self) -> bool:
        if self.ip_address is None:
            return False
        pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
        if pattern.match(self.ip_address):
            parts = self.ip_address.split(".")
            return all(0 <= int(part) <= 255 for part in parts)
        return False

    @staticmethod
    def extract_ipv4_address(message: str) -> Optional[str]:
        match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', message)
        if match:
            return match.group(0)
        return None

    @abstractmethod
    def __repr__(self) -> str:
        pass

    @abstractmethod
    def validate(self) -> bool:
        pass

    @classmethod
    @abstractmethod
    def from_dict(cls, dict: Dict[str, Any]) -> 'SSHLogEntry':
        pass

    @property
    def has_ip(self) -> bool:
        return self.ip_address is not None


class OdrzucenieHasla(SSHLogEntry):
    def __init__(self, timestamp: str, message: str, pid: int, hostname: str, ip_address: Optional[str] = None):
        super().__init__(timestamp, message, pid, hostname, ip_address)

    def __repr__(self) -> str:
        return f"OdrzucenieHasla(timestamp={self.timestamp}, message={self.message}, pid={self.pid}, hostname={self.hostname}, ip_address={self.ip_address})"

    def validate(self) -> bool:
        return True

    @classmethod
    def from_dict(cls, dict: Dict[str, Any]) -> 'OdrzucenieHasla':
        timestamp = dict.get("timestamp")
        message = dict.get("message")
        pid = dict.get("pid")
        hostname = dict.get("hostname")
        ip_address = cls.extract_ipv4_address(message)
        return cls(timestamp, message, pid, hostname, ip_address)


class AkceptacjaHasla(SSHLogEntry):
    def __init__(self, timestamp: str, message: str, pid: int, hostname: str, ip_address: Optional[str] = None):
        super().__init__(timestamp, message, pid, hostname, ip_address)

    def __repr__(self) -> str:
        return f"AkceptacjaHasla(timestamp={self.timestamp}, message={self.message}, pid={self.pid}, hostname={self.hostname}, ip_address={self.ip_address})"

    def validate(self) -> bool:
        return True

    @classmethod
    def from_dict(cls, dict: Dict[str, Any]) -> 'AkceptacjaHasla':
        timestamp = dict.get("timestamp")
        message = dict.get("message")
        pid = dict.get("pid")
        hostname = dict.get("hostname")
        ip_address = cls.extract_ipv4_address(message)
        return cls(timestamp, message, pid, hostname, ip_address)


class Blad(SSHLogEntry):
    def __init__(self, timestamp: str, message: str, pid: int, hostname: str, ip_address: Optional[str] = None):
        super().__init__(timestamp, message, pid, hostname, ip_address)

    def __repr__(self) -> str:
        return f"Blad(timestamp={self.timestamp}, message={self.message}, pid={self.pid}, hostname={self.hostname}, ip_address={self.ip_address})"

    def validate(self) -> bool:
        return True

    @classmethod
    def from_dict(cls, dict: Dict[str, Any]) -> 'Blad':
        timestamp = dict.get("timestamp")
        message = dict.get("message")
        pid = dict.get("pid")
        hostname = dict.get("hostname")
        ip_address = cls.extract_ipv4_address(message)
        return cls(timestamp, message, pid, hostname, ip_address)


class Inne(SSHLogEntry):
    def __init__(self, timestamp: str, message: str, pid: int, hostname: str, ip_address: Optional[str] = None):
        super().__init__(timestamp, message, pid, hostname, ip_address)

    def __repr__(self) -> str:
        return f"Inne(timestamp={self.timestamp}, message={self.message}, pid={self.pid}, hostname={self.hostname}, ip_address={self.ip_address})"

    def validate(self) -> bool:
        return True

    @classmethod
    def from_dict(cls, dict: Dict[str, Any]) -> 'Inne':
        timestamp = dict.get("timestamp")
        message = dict.get("message")
        pid = dict.get("pid")
        hostname = dict.get("hostname")
        ip_address = cls.extract_ipv4_address(message)
        return cls(timestamp, message, pid, hostname, ip_address)
