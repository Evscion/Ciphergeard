import math

class AffineCipherError(Exception):
    pass

class AffineCipher:
    def __init__(self, a: int, b: int, case_sensitive: bool = False) -> None:
        """
        The `Affine Cipher <https://en.wikipedia.org/wiki/Affine_cipher>`_, a classic monoalphabetic substitution cipher in Python.
        It utilizes the algebraic method for encoding and decoding messages.
        The cipher is insensitive to case by default, but can be specified to be case-sensitive. If insensitive, all the characters will be lowercased before processing.

        Encoding: E(x) = (ax + b) mod 26
        Decoding: D(x) = (1/a)(x - b) mod 26

        ---------------------------

        :param a: The multiplicative integer (must be co-prime with 26).
        :type a: int

        :param b: The additive integer.
        :type b: int 

        :param case_sensitive: Indicates whether the cipher should be case-sensitive or not, defaults to `False`.
        :type case_sensitive: bool, optional.

        ---------------------------

        :raises AffineCipherError: Indicates an error while initializing.

        ---------------------------

        **Example**
        ---------------------------
        .. code-block:: python
        
           from ciphergeard.affine import AffineCipher

           cipher = AffineCipher(a=3, b=5, case_sensitive=True)

           plaintext = "ATTACK AT DAWN"

           ciphertext = cipher.encode(plaintext=plaintext)
           # Output: FKKFLJ FK OFTS

           plaintext = cipher.decode(ciphertext=ciphertext)
           # Output: ATTACK AT DAWN
        """
        self.a = a
        if math.gcd(self.a, 26) != 1:
            raise AffineCipherError("Expected 'a' to be co-prime with 26.")
        self.ia = pow(base=self.a, exp=-1, mod=26)
        self.b = b
        self.case_sensitive = case_sensitive

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
        plaintext = plaintext.strip()
        if not self.case_sensitive:
            plaintext = plaintext.lower()

        ciphertext = ""

        for i in plaintext:
            if not i.isalpha():
                ciphertext += i
                continue
            ciphertext += chr((((self.a * self.get_index(i)) + self.b) % 26) + (65 if i.isupper() else 97))
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
        ciphertext = ciphertext.strip()
        if not self.case_sensitive:
            ciphertext = ciphertext.lower()

        plaintext = ""

        for i in ciphertext:
            if not i.isalpha():
                plaintext += i
                continue
            plaintext += chr(((self.ia * (self.get_index(i) - self.b)) % 26) + (65 if i.isupper() else 97))

        return plaintext
    
    def get_index(self, letter: str):
        """
        Used to get the index of a letter.
        
        ---------------------------

        :param letter: The letter to get the index of.
        :type letter: str
        
        ---------------------------

        :return: The index of the specified letter.
        :rtype: int

        ---------------------------
        
        :raises AffineCipherError: Indicates that the specified letter was not valid.
        """
        return ord(letter) - (65 if letter.isupper() else 97)