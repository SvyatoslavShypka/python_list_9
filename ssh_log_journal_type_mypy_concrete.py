from ssh_log_entry_type_mypy_concrete import OdrzucenieHasla, AkceptacjaHasla, Blad, Inne
from typing import List, Iterator, Dict, Any
from ssh_log_entry_type_mypy_concrete import SSHLogEntry


class SSHLogJournal:
    def __init__(self):
        self.entries: List[SSHLogEntry] = []

    def append(self, entry_data: Dict[str, Any]) -> None:
        message = entry_data.get('message', '')
        if 'Accepted password' in message:
            entry = AkceptacjaHasla.from_dict(entry_data)
        elif 'Failed password' in message:
            entry = OdrzucenieHasla.from_dict(entry_data)
        elif 'error' in message:
            entry = Blad.from_dict(entry_data)
        else:
            entry = Inne.from_dict(entry_data)
        self.entries.append(entry)

    def __iter__(self) -> Iterator[SSHLogEntry]:
        return iter(self.entries)

    def __len__(self) -> int:
        return len(self.entries)

    def filter(self, ip_address: str) -> List[SSHLogEntry]:
        return [entry for entry in self.entries if entry.has_ip and entry.ip_address == ip_address]
