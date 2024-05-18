from read_log import read_log
from ssh_log_entry import SSHLogEntry
from lab_5_1_3statistics import convert_str_to_datetime

if __name__ == '__main__':
    lista_dict = read_log(None)

    # test_log_entry.__init__
    test_log_entry = SSHLogEntry(convert_str_to_datetime(lista_dict[0].get("date")),
                            lista_dict[0].get("message"), lista_dict[0].get("PID"), lista_dict[0].get("hostname"))
    # Testujemy metodę __str__ na obiekcie test_log_entry
    print(type(test_log_entry))
    print(test_log_entry)
    # Testujemy metodę extract_ipv4_address
    print(type(test_log_entry.extract_ipv4_address()))
    print(test_log_entry.extract_ipv4_address())

    # TEST:    type SSH.log | python lab_6_1.py
