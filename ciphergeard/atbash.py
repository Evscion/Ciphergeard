import string

class AtbashCipherError(Exception):
    pass

class AtbashCipher:
    def __init__(self) -> None:
        """
        The `Atbash Cipher <https://en.wikipedia.org/wiki/Atbash>`_, a class monoalphabetic substitution cipher.
        The cipher is not case-sensitive, so both plaintext and encoded text are converted to lowercase during processing.

        It maps the alphabets to their reverse ones.
        For eg. A <-> Z or S <-> H

        **Example**
        ---------------------------
        .. code-block:: python
        
           from ciphergeard.atbash import AtbashCipher

           cipher = AtbashCipher()

           plaintext = "ATTACK AT DAWN"

           ciphertext = cipher.encode(plaintext=plaintext)
           # Output: zggzxp zg wzdm

           plaintext = cipher.decode(ciphertext=ciphertext)
           # Output: attack at dawn
        """
        pass

    def encode(self, plaintext: str):
        """
        Used to encode the `plaintext`.

        ---------------------------

        :param plaintext: The plaintext to encode.
        :type plaintext: str

        ---------------------------

        :return: The encoded text.
        :rtype: str
        """
        plaintext = plaintext.lower().strip()
        ciphertext = ""

        for i in plaintext:
            if not i.isalpha():
                ciphertext += i
                continue
            ciphertext += string.ascii_lowercase[25 - self.get_index(i)]
            continue

        return ciphertext

    def decode(self, ciphertext: str):
        """
        Used to decode the `ciphertext`.

        ---------------------------

        :param ciphertext: The encoded text to decode.
        :type ciphertext: str

        ---------------------------

        :return: The decoded text.
        :rtype: str
        """
        ciphertext.lower().strip()
        plaintext = ""

        for i in ciphertext:
            if not i.isalpha():
                plaintext += i
                continue
            plaintext += string.ascii_lowercase[25 - self.get_index(i)]

        return plaintext
    
    def get_index(self, letter: str):
        """
        Used to return the index of a letter.

        ---------------------------

        :param letter: The letter to get the index of.
        :type letter: str

        ---------------------------

        :return: The index of the specified letter.
        :rtype: int

        ---------------------------

        :raises AtbashCipherError: Indicates that the specified letter was not valid.
        """
        res = string.ascii_lowercase.find(letter.lower().strip())
        if res == -1:
            raise AtbashCipherError(f"Expected a valid lowercase letter. Found: {letter}")
        return res