from ssh_log_entry_type import SSHLogEntry
from read_log import read_lines
from ssh_log_journal_type import SSHLogJournal
from typing import List


# Funkcja filtrująca logi dla konkretnego adresu IP
def filter_by_ip_address(entry: SSHLogEntry, ip_address: str) -> bool:
    if hasattr(entry, 'message') and ip_address in entry.message:
        return True
    elif hasattr(entry, 'error_message') and ip_address in entry.error_message:
        return True
    elif hasattr(entry, 'ip_address') and ip_address in entry.ip_address:
        return True
    else:
        return False


if __name__ == '__main__':
    journal: SSHLogJournal = SSHLogJournal()
    lines: List[str] = read_lines(None)  # Assuming read_lines(None) returns a list of log lines

    for line in lines:
        journal.append(line)

    print(len(journal))

    for entry in journal:
        print(entry)

    # Filtrowanie logów dla adresu IP 119.137.62.142
    filtered_logs: List[SSHLogEntry] = [entry for entry in journal if filter_by_ip_address(entry, "119.137.62.142")]

    # Sprawdzenie, czy filtrowanie działa poprawnie
    print("-----------------filtered logs-----------------------")
    for entry in filtered_logs:
        print(entry)

    # TEST:    type regexp.log | python lab_9_1.py
