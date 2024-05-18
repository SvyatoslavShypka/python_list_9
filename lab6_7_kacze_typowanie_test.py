from read_log import read_lines
from ssh_log_entry_abstract import AkceptacjaHasla
from ssh_log_journal import SSHLogJournal
from lab6_7_kacze_typowanie import SSHUser

if __name__ == '__main__':
    journal = SSHLogJournal()
    lines = read_lines(None)
    for line in lines:
        journal.append(line)
    users = []
    for entry in journal.entries:
        if isinstance(entry, AkceptacjaHasla):
            users.append(SSHUser(entry.user, entry.timestamp))

    # Kacze typowanie poprzez iterację po liście i wywoływanie metody validate()
    for user in users:
        if user.validate():
            print(f"Użytkownik {user.username} jest poprawny.")
        else:
            print(f"Użytkownik {user.username} jest niepoprawny.")

    # TEST: short:    type regexp.log | python lab6_7_kacze_typowanie_test.py
    # TEST: long:     type SSH.log | python lab6_7_kacze_typowanie_test.py

