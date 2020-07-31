from models.Utils import verify, decrypt
from collections import defaultdict


class VS:
    def __init__(self, key_pair):
        self.key_pair = key_pair
        self.voters = []
        self.candidates = defaultdict(lambda: 0)

    def get_pub_key(self):
        self.pub_key = self.key_pair.publickey()
        return self.pub_key

    def receive_vote(self, message, voter_pub_key, as_pub_key):
        token, encrypted_selected_candidate, encrypted_i_code, signed_selected_candidate, \
        signed_i_code = message

        v_candidate = verify(encrypted_selected_candidate, signed_selected_candidate, voter_pub_key)
        v_i_code = verify(encrypted_i_code, signed_i_code, voter_pub_key)
        if v_i_code and v_candidate:
            candidate = decrypt(encrypted_selected_candidate, self.key_pair)
            i_code = decrypt(encrypted_i_code, self.key_pair)
            verify_t = verify(i_code, token, as_pub_key)
            if verify_t:
                if hash(i_code) not in self.voters:
                    self.voters.append(hash(i_code))
                    self.candidates[candidate] += 1

    def present_selected_candidate(self):
        max_vote = -1
        selected = None
        for key in self.candidates.keys():
            if self.candidates[key] > max_vote:
                max_vote = self.candidates[key]
                selected = key
        return selected
