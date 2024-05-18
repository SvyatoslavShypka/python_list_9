import re
from ssh_log_entry_abstract import SSHLogEntry, OdrzucenieHasla, AkceptacjaHasla, Blad, Inne
from read_log import parsing_line
from lab_5_1_3statistics import convert_str_to_datetime


class SSHLogJournal:
    def __init__(self):
        self.entries = []

    def append(self, wiersz):
        # Tworzymy nowy obiekt SSHLogEntry na podstawie ciągu log_string
        # Możemy użyć odpowiednich funkcji z poprzednich implementacji
        # Tutaj użyłem log_string jako przykładu, możesz dostosować to do swojej implementacji
        # Załóżmy, że log_string jest ciągiem logu SSH
        new_log = self.create_ssh_log_entry(wiersz)

        # Jeśli nowy log jest ważny (przeszedł walidację), dodajemy go do listy
        if new_log:
            self.entries.append(new_log)

    def create_ssh_log_entry(self, wiersz):
        # Tworzymy obiekt SSHLogEntry na podstawie ciągu log_string
        # oraz jego walidację. Ta logika będzie zależeć od twojej implementacji SSHLogEntry.

        # Załóżmy, że log_string jest ciągiem logu SSH
        # Tutaj można użyć odpowiednich metod do parsowania log_string i tworzenia obiektu SSHLogEntry
        # Na przykład, jeśli log_string jest w formacie JSON, można go sparsować i wyodrębnić potrzebne informacje

        # Poniżej przykład prosty dla celów demonstracyjnych
        # Zakładam, że log_string zawiera datę, wiadomość i ewentualnie adres IP
        log_entry = parsing_line(wiersz)
        if "Accepted password" in wiersz:
            new_log = AkceptacjaHasla.from_dict(log_entry)
        elif "Failed password" in wiersz:
            new_log = OdrzucenieHasla.from_dict(log_entry)
        elif "error" in wiersz.lower():
            new_log = Blad.from_dict(log_entry)
        else:
            new_log = Inne.from_dict(log_entry)
        # Walidujemy log i zwracamy go tylko jeśli jest poprawny
        if new_log.validate():
            return new_log
        else:
            return None

    def __len__(self):
        return len(self.entries)

    def __iter__(self):
        return iter(self.entries)

    def __contains__(self, item):
        return item in self.entries

    def filter_by_ip(self, criteria):
        # Metoda do filtrowania listy logów na podstawie wybranego kryterium
        # criteria to funkcja, która przyjmuje SSHLogEntry jako argument i zwraca True lub False
        return [entry for entry in self.entries if criteria(entry)]
