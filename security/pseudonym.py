import secrets


class PseudonymManager:

    def __init__(self):
        self.vehicle_pseudonyms = {}

    def generate_pseudonym(self, vehicle_id):

        pseudonym = "PSEUDO_" + secrets.token_hex(3).upper()

        self.vehicle_pseudonyms[pseudonym] = vehicle_id

        return pseudonym

    def get_vehicle_id(self, pseudonym):
        return self.vehicle_pseudonyms.get(pseudonym)
