import re


class SSHUser:
    def __init__(self, username, last_login_date):
        self.username = username
        self.last_login_date = last_login_date

    def validate(self):
        # Walidacja nazwy użytkownika
        pattern = r'^[a-z_][a-z0-9_-]{0,3}$'   # testowo - nie więcej jak 4 znaki
        if re.match(pattern, self.username):
            return True
        else:
            return False