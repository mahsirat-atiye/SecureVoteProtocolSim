from models.CA import CA
from models.Voter import Voter

ca = CA()
authentication_server = ca.create_AS()
voting_server = ca.create_vs()

voter1 = Voter("002-036-135", "123-a")

"""
Voter sends request to CA to have pub key & prv key.
Using CA pub_key
"""

message_from_voter_to_ca = voter1.pub_prv_key_request_to_ca(ca.get_pub_key_of("CA"))
"""
CA responses to request, by checking credentials & generating prv pub key if it is anew registration!
"""
print("here")
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
CA verifies the message & decrypt it
"""
message_from_as_to_voter = authentication_server.response_to_authentication_request_part3(message_from_ca_to_as,  ca.get_pub_key_of("CA"), ca )
# a =(ca.get_pub_key_of(voter1.national_code))
# b = (message_from_as_to_voter)
#
# aa = a.exportKey()
# bb = b.publickey().exportKey()
# print(aa)
# print("--------")
# print(bb)
#
# print(aa == bb)
