from parsing import parsing_line
from read_log import read_lines
from ssh_log_journal_type_mypy import SSHLogJournal

if __name__ == '__main__':
    journal = SSHLogJournal()
    lines = read_lines(None)
    for line in lines:
        # Assuming parsing_line converts each line into a dictionary
        log_dict = parsing_line(line)
        if log_dict:
            journal.append(log_dict)
    print(len(journal))

    for entry in journal:
        print(entry)

    # Filtrowanie logów dla adresu IP 119.137.62.142
    filtered_logs = journal.filter("119.137.62.142")

    # Sprawdzenie, czy filtrowanie działa poprawnie
    print("-----------------filtered logs-----------------------")
    for entry in filtered_logs:
        print(entry)
