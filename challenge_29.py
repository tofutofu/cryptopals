# Break a SHA-1 keyed MAC using length extension
#
# Quote:
#   "Secret-prefix SHA-1 MACs are trivially breakable."
#
# The cryptopals explanation in this challenge is muddled and confusing.
#
# A clear explanation of what the length-extension attack involves can be found at:
# https://crypto.stackexchange.com/questions/3978/understanding-the-length-extension-attack
#
# Function challenge_28.test2 illustrates the principle.
#

from typing import Callable
from challenge_28 import sha1, padding, sign, verify


def forge(
    msg: bytes, mac: str, payload: bytes, is_valid: Callable[[bytes, str], bool]
) -> tuple:
    n = len(msg)

    for k in range(128):
        # guessed padding of the message (including the hidden key)
        glue = padding(k + n)

        # we need to add the glue to align the payload on a 512-bit boundary
        # and to continue from the known MAC
        new_msg = msg + glue + payload

        # we continue from the known MAC, but need to set the total message length
        # to the length of the new_msg to get the right padding
        new_mac = sha1(payload, hh=mac, msg_len=len(new_msg) + k)

        if is_valid(new_msg, new_mac):  # type: ignore
            return new_msg, new_mac

    return None, None


def test(key=b"expialidocious"):
    """
    Takes a message and use the MAC to forge another message that authenticates as valid.
    """

    def is_valid(msg: bytes, mac: str) -> bool:
        return verify(msg, mac, key)

    msg = (
        b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    )
    mac = sign(msg, key)
    assert is_valid(msg, mac)

    print("Msg", msg)
    print("MAC", mac)
    print()

    payload = b";admin=true"
    forged_msg, new_mac = forge(msg, mac, payload=payload, is_valid=is_valid)

    if forged_msg is not None:
        assert forged_msg.endswith(payload)
        assert is_valid(forged_msg, new_mac)
        print("New msg", forged_msg)
        print("New MAC", new_mac)
    else:
        print("Failed")


if __name__ == "__main__":
    test()
