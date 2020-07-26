from models.CA import CA
from models.Voter import Voter

ca = CA()
authentication_server = ca.create_AS()
voting_server = ca.create_vs()

voter1 = Voter("002-036-135", "123-a")
code, key = voter1.get_auth_symmetric_key()
authentication_server.add_symmetric_key(code, key)
"""
Voter sends request to CA to have pub key & prv key.
Using CA pub_key
"""

message_from_voter_to_ca = voter1.pub_prv_key_request_to_ca(ca.get_pub_key_of("CA"))
"""
CA responses to request, by checking credentials & generating prv pub key if it is anew registration!
"""
ca.response_to_pub_prv_key_request(message_from_voter_to_ca)
"""
Voter sends its identities to authentication server to be authenticated using AS pub key!
"""
message_from_voter_to_as = voter1.authentication_request(ca.get_pub_key_of("AS"))
"""
AS receives the message & decrypt it and sign it and encrypt it by ca pub key & forward it to CA
"""

message_from_as_to_ca = authentication_server.response_to_authentication_request_part1(message_from_voter_to_as,
                                                                                       ca.get_pub_key_of("CA"))
"""
CA sends prv key & pub key to AS by signing it and encrypt it by AS pub key 
"""
message_from_ca_to_as = ca.response_to_authentication_request_part2(message_from_as_to_ca)
"""
AS receives the keys and verify it and sign it and send it voter by using symmetric encryption
"""
message_from_as_to_voter = authentication_server.response_to_authentication_request_part3(message_from_ca_to_as,
                                                                                          ca.get_pub_key_of("CA"))
"""
Voter receives its key pair and check its national code with generated token, then uses the token to send his vote
"""
message_from_voter_to_vs = voter1.voting_request_after_auth(message_from_as_to_voter,   ca.get_pub_key_of("AS"))

"""print
Voting system...

"""

selected_candid = ""
