from read_log import read_log
from ssh_log_entry_abstract import OdrzucenieHasla, AkceptacjaHasla, Blad, Inne


if __name__ == '__main__':
    lista_dict = read_log(None)
    for dict in lista_dict:
        if "Accepted password" in dict.get("message"):
            akceptacja_hasla_message = dict
        elif "Failed password" in dict.get("message"):
            odrzucenie_hasla_message = dict
        elif "error" in dict.get("message").lower():
            blad_message = dict
        else:
            inne_message = dict

    # Tworzymy objekty dziedziczonych klas
    odrzucenie_hasla_objekt = OdrzucenieHasla.from_dict(odrzucenie_hasla_message)
    akceptacja_hasla_objekt = AkceptacjaHasla.from_dict(akceptacja_hasla_message)
    blad_objekt = Blad.from_dict(blad_message)
    inne_objekt = Inne.from_dict(inne_message)

    # Testujemy metody validate
    print("Validating failed password entry:", odrzucenie_hasla_objekt.validate())  # True
    print("Validating accepted password entry:", akceptacja_hasla_objekt.validate())  # True
    print("Validating error entry:", blad_objekt.validate())  # True
    print("Validating inne entry:", inne_objekt.validate())  # True

    # Testujemy właściwość has_ip
    print("Failed password entry has IP:", odrzucenie_hasla_objekt.has_ip)  # True
    print("Accepted password entry has IP:", akceptacja_hasla_objekt.has_ip)  # True
    print("Error entry has IP:", blad_objekt.has_ip)  # True
    print("Inne entry has IP:", inne_objekt.has_ip)  # True

    # Testujemy metody magiczne __repr__, __eq__, __lt__, __gt__
    print("Repr of failed password entry:", repr(odrzucenie_hasla_objekt))
    print("Repr of accepted password entry:", repr(akceptacja_hasla_objekt))
    print("Repr of error entry:", repr(blad_objekt))
    print("Repr of inne entry:", repr(inne_objekt))

    print("Failed password entry is equal to accepted password entry:",
          odrzucenie_hasla_objekt == akceptacja_hasla_objekt)  # False
    print("Failed password entry is equal to itself:", odrzucenie_hasla_objekt == odrzucenie_hasla_objekt)  # True

    print("Failed password entry is less than accepted password entry:",
          odrzucenie_hasla_objekt < akceptacja_hasla_objekt)  # True
    print("Accepted password entry is less than failed password entry:",
          akceptacja_hasla_objekt < odrzucenie_hasla_objekt)  # False

    print("Failed password entry is greater than accepted password entry:",
          odrzucenie_hasla_objekt > akceptacja_hasla_objekt)  # False
    print("Accepted password entry is greater than failed password entry:",
          akceptacja_hasla_objekt > odrzucenie_hasla_objekt)  # True


    # TEST:    type SSH.log | python lab_6_3-6_test.py
