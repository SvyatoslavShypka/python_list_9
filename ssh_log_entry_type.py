from abc import ABC, abstractmethod
import re
from datetime import datetime
from typing import Optional, Dict, Union
from ipaddress import IPv4Address

from lab_5_1_1 import get_user_from_log, get_ipv4s_from_log
from lab_5_1_3statistics import convert_str_to_datetime


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
                    self.pid == other.pid and
                    self.hostname == other.hostname)
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
    def from_dict(cls, dict: Dict[str, Union[str, int]]) -> 'OdrzucenieHasla':
        timestamp: datetime = convert_str_to_datetime(dict.get("date"))
        pid: Optional[int] = dict.get("PID")
        hostname: Optional[str] = dict.get("hostname")
        user: Optional[str] = get_user_from_log(dict)
        ip_address: Optional[str] = get_ipv4s_from_log(dict)
        return cls(timestamp, dict.get("message"), pid, hostname, user, ip_address)

    def __repr__(self) -> str:
        return f"FailedPasswordEntry(timestamp={self.timestamp}, message={self._raw_message}, pid={self.pid}, hostname={self.hostname}, user={self.user}, ip_address={self.ip_address})"


class AkceptacjaHasla(SSHLogEntry):
    def __init__(self, timestamp: datetime, message: str, pid: Optional[int] = None, hostname: Optional[str] = None, user: Optional[str] = None, ip_address: Optional[str] = None):
        super().__init__(timestamp, message, pid, hostname)
        self.user: Optional[str] = user
        self.ip_address: Optional[str] = ip_address

    def validate(self) -> bool:
        return "Accepted password" in self._raw_message

    @classmethod
    def from_dict(cls, dict: Dict[str, Union[str, int]]) -> 'AkceptacjaHasla':
        timestamp: datetime = convert_str_to_datetime(dict.get("date"))
        pid: Optional[int] = dict.get("PID")
        hostname: Optional[str] = dict.get("hostname")
        user: Optional[str] = get_user_from_log(dict)
        ip_address: Optional[str] = get_ipv4s_from_log(dict)
        return cls(timestamp, dict.get("message"), pid, hostname, user, ip_address)

    def __repr__(self) -> str:
        return f"AcceptedPasswordEntry(timestamp={self.timestamp}, message={self._raw_message}, pid={self.pid}, hostname={self.hostname}, user={self.user}, ip_address={self.ip_address})"


class Blad(SSHLogEntry):
    def __init__(self, timestamp: datetime, message: str, pid: Optional[int] = None, hostname: Optional[str] = None, error_message: Optional[str] = None):
        super().__init__(timestamp, message, pid, hostname)
        self.error_message: Optional[str] = error_message

    def validate(self) -> bool:
        return "error" in self._raw_message.lower()

    @classmethod
    def from_dict(cls, dict: Dict[str, Union[str, int]]) -> 'Blad':
        timestamp: datetime = convert_str_to_datetime(dict.get("date"))
        pid: Optional[int] = dict.get("PID")
        hostname: Optional[str] = dict.get("hostname")
        blad_message: Optional[str] = dict.get("message")
        return cls(timestamp, dict.get("message"), pid, hostname, blad_message)

    def __repr__(self) -> str:
        return f"ErrorEntry(timestamp={self.timestamp}, message={self._raw_message}, pid={self.pid}, hostname={self.hostname}, error_message={self.error_message})"


class Inne(SSHLogEntry):
    def __init__(self, timestamp: datetime, message: str, pid: Optional[int] = None, hostname: Optional[str] = None, error_message: Optional[str] = None):
        super().__init__(timestamp, message, pid, hostname)
        self.error_message: Optional[str] = error_message

    def validate(self) -> bool:
        return True

    @classmethod
    def from_dict(cls, dict: Dict[str, Union[str, int]]) -> 'Inne':
        timestamp: datetime = convert_str_to_datetime(dict.get("date"))
        pid: Optional[int] = dict.get("PID")
        hostname: Optional[str] = dict.get("hostname")
        inne_message: Optional[str] = dict.get("message")
        return cls(timestamp, dict.get("message"), pid, hostname, inne_message)

    def __repr__(self) -> str:
        return f"InneEntry(timestamp={self.timestamp}, message={self._raw_message}, pid={self.pid}, hostname={self.hostname}, error_message={self.error_message})"
