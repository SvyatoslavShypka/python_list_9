from lab_5_1_3statistics import convert_str_to_datetime
from ssh_log_entry import SSHLogEntry
from lab_5_1_1 import get_user_from_log, get_ipv4s_from_log


class OdrzucenieHasla(SSHLogEntry):
    def __init__(self, timestamp, message, pid=None, hostname=None, user=None, ip_address=None):
        super().__init__(timestamp, message, pid, hostname)
        self.user = user
        self.ip_address = ip_address

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


class AkceptacjaHasla(SSHLogEntry):
    def __init__(self, timestamp, message, pid=None, hostname=None, user=None, ip_address=None):
        super().__init__(timestamp, message, pid, hostname)
        self.user = user
        self.ip_address = ip_address

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


class Blad(SSHLogEntry):
    def __init__(self, timestamp, message, pid=None, hostname=None, blad_message=None):
        super().__init__(timestamp, message, pid, hostname)
        self.blad_message = blad_message

    @classmethod
    def from_dict(cls, dict):
        # Wyodrębniamy potrzebne informacje z dict
        timestamp = convert_str_to_datetime(dict.get("date"))
        pid = dict.get("PID")
        hostname = dict.get("hostname")
        blad_message = dict.get("message")
        return cls(timestamp, dict.get("message"), pid, hostname, blad_message)


class Inne(SSHLogEntry):
    def __init__(self, timestamp, message, pid=None, hostname=None, inne_message=None):
        super().__init__(timestamp, message, pid, hostname)
        self.inne_message = inne_message

    @classmethod
    def from_dict(cls, dict):
        # Wyodrębniamy potrzebne informacje z dict
        timestamp = convert_str_to_datetime(dict.get("date"))
        pid = dict.get("PID")
        hostname = dict.get("hostname")
        inne_message = dict.get("message")
        return cls(timestamp, dict.get("message"), pid, hostname, inne_message)
