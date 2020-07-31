from models.CA import CA
from models.Voter import Voter


# Note: you may need to run the code twice!


def vote_protocol(ca, authentication_server, voting_server, voter1):
    """
    generating symmetric key for AS and voter
    """
    code, key = voter1.get_auth_symmetric_key()
    authentication_server.add_symmetric_key(code, key)

    """
    Voter sends request to CA to have pub key & prv key.
    Using CA pub_key
    E_ca_pub (national_code, certificate_num)
    """
    message_from_voter_to_ca = voter1.pub_prv_key_request_to_ca(ca.get_pub_key_of("CA"))

    """
    CA responses to request, by checking credentials & generating prv pub key if it is a new registration!
    """
    ca.response_to_pub_prv_key_request(message_from_voter_to_ca)

    """
    Voter sends its identities to authentication server to be authenticated using AS pub key!
    E_as_pub (national_code, certificate_num)
    """
    message_from_voter_to_as = voter1.authentication_request(ca.get_pub_key_of("AS"))

    """
    AS receives the message & decrypt it, and then sign it and encrypt it by ca pub key & forward it to CA
        E_ca_pub (national_code, certificate_num), Sign_as_prv (E_ca_pub (national_code, certificate_num))
    """
    message_from_as_to_ca = authentication_server.response_to_authentication_request_part1(message_from_voter_to_as,
                                                                                           ca.get_pub_key_of("CA"))

    """
    CA sends prv key & pub key to AS by signing it and encrypt it by AS pub key 
    E_as_pub(key_pair), Sign_ca_prv(E_as_pub(key_pair)), E_as_pub(national id), Sign_ca_prv(E_as_pub(national id))
    """
    message_from_ca_to_as = ca.response_to_authentication_request_part2(message_from_as_to_ca)

    """
    AS receives the keys and verify it and sign it and send it voter by using symmetric encryption
    Token = E_voter_pub(Sing_as_prv (national id))
    E_symmetric_key(Token, national id, key pair), Sign_as_prv(E_symmetric_key(Token, national id, key pair))
    """
    message_from_as_to_voter = authentication_server.response_to_authentication_request_part3(message_from_ca_to_as,
                                                                                              ca.get_pub_key_of("CA"))

    """
    Voter receives its key pair and check its national code with generated token, then uses the token to send his vote
    Token, E_vs_pub(national id, candidate), Sign_voter_prv (E_vs_pub(national id, candidate))
    """
    message_from_voter_to_vs = voter1.voting_request_after_auth(message_from_as_to_voter, ca.get_pub_key_of("AS"),
                                                                ca.get_pub_key_of("VS"))

    """
    Voting system checks the token to verify the national code and records the vote
    """
    record_vote = voting_server.receive_vote(message_from_voter_to_vs, ca.get_pub_key_of(voter1.national_code),
                                             ca.get_pub_key_of("AS"))


if __name__ == '__main__':
    ca = CA()
    authentication_server = ca.create_AS()
    voting_server = ca.create_vs()

    voter1 = Voter("002-036-135", "123-a", "Hasan Rohani")

    vote_protocol(ca, authentication_server, voting_server, voter1)
    selected_candid = voting_server.present_selected_candidate()
    print(selected_candid)
