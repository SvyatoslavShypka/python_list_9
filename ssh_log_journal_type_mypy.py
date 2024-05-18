from ssh_log_entry_type_mypy import OdrzucenieHasla, AkceptacjaHasla, Blad, Inne
from typing import List, Iterator, Dict, Any, Optional
from ssh_log_entry_type_mypy import SSHLogEntry


class SSHLogJournal:
    def __init__(self):
        self.entries: List[SSHLogEntry] = []

    def append(self, wiersz: Dict[str, Any]) -> None:
        new_entry_accepted: Optional[AkceptacjaHasla] = None
        new_entry_failed: Optional[OdrzucenieHasla] = None
        new_entry_error: Optional[Blad] = None
        new_entry_other: Optional[Inne] = None

        if 'Accepted password' in wiersz.get('message', ''):
            new_entry_accepted = AkceptacjaHasla.from_dict(wiersz)
            if new_entry_accepted.validate():
                self.entries.append(new_entry_accepted)

        elif 'Failed password' in wiersz.get('message', ''):
            new_entry_failed = OdrzucenieHasla.from_dict(wiersz)
            if new_entry_failed.validate():
                self.entries.append(new_entry_failed)

        elif 'error' in wiersz.get('message', '').lower():
            new_entry_error = Blad.from_dict(wiersz)
            if new_entry_error.validate():
                self.entries.append(new_entry_error)

        else:
            new_entry_other = Inne.from_dict(wiersz)
            if new_entry_other.validate():
                self.entries.append(new_entry_other)

    def __iter__(self) -> Iterator[SSHLogEntry]:
        return iter(self.entries)

    def __len__(self) -> int:
        return len(self.entries)

    def filter(self, ip_address: str) -> List[SSHLogEntry]:
        return [entry for entry in self.entries if entry.has_ip and ip_address in entry._raw_message]
