import pytest
from ssh_log_entry_type_mypy_concrete import AkceptacjaHasla, OdrzucenieHasla, Blad, Inne
from ssh_log_journal_type_mypy_concrete import SSHLogJournal


@pytest.fixture
def sample_entry_data():
    return {'hostname': 'example.com', 'message': 'Sample log message with timestamp', 'pid': 1234, 'timestamp': '2024-05-18 12:00:00'}


def test_extract_timestamp(sample_entry_data):
    entry = AkceptacjaHasla.from_dict(sample_entry_data)
    assert entry.timestamp == sample_entry_data['timestamp']


@pytest.mark.parametrize("ip_address, expected_result", [
    ("173.234.31.186", True),  # Poprawny IP adres
    ("666.777.88.213", False),  # Niepoprawny IP adres
    ("", False)  # Jeżeli nie ma IP adresu
])
def test_extract_ipv4_address(ip_address, expected_result, sample_entry_data):
    sample_entry_data['message'] = f"Sample log message with IP {ip_address}"
    entry = AkceptacjaHasla.from_dict(sample_entry_data)
    assert entry.validate_ip_address() == expected_result


@pytest.mark.parametrize("entry_data, expected_class", [
    ({"timestamp": "2024-05-18 12:00:00", "message": "Failed password for invalid user", "pid": 1234, "hostname": "example.com"}, OdrzucenieHasla),
    ({"timestamp": "2024-05-18 12:00:00", "message": "Accepted password for user", "pid": 1234, "hostname": "example.com"}, AkceptacjaHasla),
    ({"timestamp": "2024-05-18 12:00:00", "message": "error: Could not connect to server", "pid": 1234, "hostname": "example.com"}, Blad),
    ({"timestamp": "2024-05-18 12:00:00", "message": "Unrecognized entry", "pid": 1234, "hostname": "example.com"}, Inne)
])
def test_append_entry_type(entry_data, expected_class):
    journal = SSHLogJournal()
    journal.append(entry_data)

    # Check the last entry in the journal
    assert isinstance(journal.entries[-1], expected_class)
    assert journal.entries[-1].timestamp == entry_data['timestamp']
    assert journal.entries[-1].message == entry_data['message']

# TEST lab_9.3:  pytest test_ssh_log_entry.py
