from abc import ABC, abstractmethod
import re
from lab_5_1_3statistics import convert_str_to_datetime
from lab_5_1_1 import get_user_from_log, get_ipv4s_from_log


class SSHLogEntry(ABC):
    def __init__(self, timestamp, message, pid=None, hostname=None):
        self._raw_message = message
        self.timestamp = timestamp
        self.pid = pid
        self.hostname = hostname

    @property
    def has_ip(self):
        return bool(self.extract_ipv4_address(self._raw_message))

    @abstractmethod
    def validate(self):
        pass

    @staticmethod
    def extract_ipv4_address(message):
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        ip_matches = re.findall(ip_pattern, message)
        if ip_matches:
            return True
        else:
            return False

    @abstractmethod
    def __repr__(self):
        return f"{self.__class__.__name__}(timestamp={self.timestamp}, " \
               f"message={self._raw_message}, pid={self.pid}, hostname={self.hostname})"

    def __eq__(self, other):
        if isinstance(other, SSHLogEntry):
            return self.timestamp == other.timestamp and \
                   self._raw_message == other._raw_message and \
                   self.pid == other.pid and \
                   self.hostname == other.hostname
        return NotImplemented

    def __lt__(self, other):
        if isinstance(other, SSHLogEntry):
            return self.timestamp < other.timestamp
        return NotImplemented

    def __gt__(self, other):
        if isinstance(other, SSHLogEntry):
            return self.timestamp > other.timestamp
        return NotImplemented


class OdrzucenieHasla(SSHLogEntry):
    def __init__(self, timestamp, message, pid=None, hostname=None, user=None, ip_address=None):
        super().__init__(timestamp, message, pid, hostname)
        self.user = user
        self.ip_address = ip_address

    def validate(self):
        return "Failed password" in self._raw_message

    @classmethod
    def from_dict(cls, dict):
        # Wyodrębniamy potrzebne informacje z dict
        timestamp = convert_str_to_datetime(dict.get("date"))
        pid = dict.get("PID")
        hostname = dict.get("hostname")
        user = get_user_from_log(dict)
        if not user:
            user = None
        ip_address = get_ipv4s_from_log(dict)
        return cls(timestamp, dict.get("message"), pid, hostname, user, ip_address)

    def __repr__(self):
        return f"FailedPasswordEntry(timestamp={self.timestamp}, message={self._raw_message}, pid={self.pid}, hostname={self.hostname}, user={self.user}, ip_address={self.ip_address})"


class AkceptacjaHasla(SSHLogEntry):
    def __init__(self, timestamp, message, pid=None, hostname=None, user=None, ip_address=None):
        super().__init__(timestamp, message, pid, hostname)
        self.user = user
        self.ip_address = ip_address

    def validate(self):
        return "Accepted password" in self._raw_message

    @classmethod
    def from_dict(cls, dict):
        # Wyodrębniamy potrzebne informacje z dict
        timestamp = convert_str_to_datetime(dict.get("date"))
        pid = dict.get("PID")
        hostname = dict.get("hostname")
        user = get_user_from_log(dict)
        if not user:
            user = None
        ip_address = get_ipv4s_from_log(dict)
        return cls(timestamp, dict.get("message"), pid, hostname, user, ip_address)

    def __repr__(self):
        return f"AcceptedPasswordEntry(timestamp={self.timestamp}, message={self._raw_message}, pid={self.pid}, hostname={self.hostname}, user={self.user}, ip_address={self.ip_address})"


class Blad(SSHLogEntry):
    def __init__(self, timestamp, message, pid=None, hostname=None, error_message=None):
        super().__init__(timestamp, message, pid, hostname)
        self.error_message = error_message

    def validate(self):
        return "error" in self._raw_message.lower()

    @classmethod
    def from_dict(cls, dict):
        # Wyodrębniamy potrzebne informacje z dict
        timestamp = convert_str_to_datetime(dict.get("date"))
        pid = dict.get("PID")
        hostname = dict.get("hostname")
        blad_message = dict.get("message")
        return cls(timestamp, dict.get("message"), pid, hostname, blad_message)

    def __repr__(self):
        return f"ErrorEntry(timestamp={self.timestamp}, message={self._raw_message}, pid={self.pid}, hostname={self.hostname}, error_message={self.error_message})"


class Inne(SSHLogEntry):
    def __init__(self, timestamp, message, pid=None, hostname=None, error_message=None):
        super().__init__(timestamp, message, pid, hostname)
        self.error_message = error_message

    def validate(self):
        return True

    @classmethod
    def from_dict(cls, dict):
        # Wyodrębniamy potrzebne informacje z dict
        timestamp = convert_str_to_datetime(dict.get("date"))
        pid = dict.get("PID")
        hostname = dict.get("hostname")
        inne_message = dict.get("message")
        return cls(timestamp, dict.get("message"), pid, hostname, inne_message)

    def __repr__(self):
        return f"InneEntry(timestamp={self.timestamp}, message={self._raw_message}, pid={self.pid}, hostname={self.hostname}, error_message={self.error_message})"
