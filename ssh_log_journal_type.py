import re
from typing import Optional, List, Callable, Any, Dict
from ssh_log_entry_abstract import SSHLogEntry, OdrzucenieHasla, AkceptacjaHasla, Blad, Inne
from read_log import parsing_line
from lab_5_1_3statistics import convert_str_to_datetime


class SSHLogJournal:
    def __init__(self):
        self.entries: List[SSHLogEntry] = []

    def append(self, wiersz: str) -> None:
        new_log: Optional[SSHLogEntry] = self.create_ssh_log_entry(wiersz)
        if new_log:
            self.entries.append(new_log)

    def create_ssh_log_entry(self, wiersz: str) -> Optional[SSHLogEntry]:
        log_entry: Dict[str, Any] = parsing_line(wiersz)
        if "Accepted password" in wiersz:
            new_log: SSHLogEntry = AkceptacjaHasla.from_dict(log_entry)
        elif "Failed password" in wiersz:
            new_log: SSHLogEntry = OdrzucenieHasla.from_dict(log_entry)
        elif "error" in wiersz.lower():
            new_log: SSHLogEntry = Blad.from_dict(log_entry)
        else:
            new_log: SSHLogEntry = Inne.from_dict(log_entry)
        if new_log.validate():
            return new_log
        else:
            return None

    def __len__(self) -> int:
        return len(self.entries)

    def __iter__(self) -> iter:
        return iter(self.entries)

    def __contains__(self, item: SSHLogEntry) -> bool:
        return item in self.entries

    def filter_by_ip(self, criteria: Callable[[SSHLogEntry], bool]) -> List[SSHLogEntry]:
        return [entry for entry in self.entries if criteria(entry)]
