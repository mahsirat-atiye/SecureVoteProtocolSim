class VS:
    def __init__(self, key_pair):
        self.key_pair = key_pair

    def get_pub_key(self):
        self.pub_key = self.key_pair.publickey()
        return self.pub_key