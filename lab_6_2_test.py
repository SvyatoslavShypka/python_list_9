from read_log import read_log
from lab_6_2_klasy import OdrzucenieHasla, AkceptacjaHasla, Blad, Inne


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

    # Testujemy wywołując metodę __str__ na instancjach
    print(odrzucenie_hasla_objekt)
    print(akceptacja_hasla_objekt)
    print(blad_objekt)
    print(inne_objekt)

    # Testujemy dodatkowe atrybuty
    print("User:", odrzucenie_hasla_objekt.user)
    print("IP Address:", odrzucenie_hasla_objekt.ip_address)

    print("User:", akceptacja_hasla_objekt.user)
    print("IP Address:", akceptacja_hasla_objekt.ip_address)

    print("Error Message:", blad_objekt.blad_message)
    print("Inny Message:", inne_objekt.inne_message)

    # TEST:    type SSH.log | python lab_6_2_test.py

