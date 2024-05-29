import random
import string

class VernamCipherError(Exception):
    pass

class VernamCipher:
    def __init__(self) -> None:
        """
        The `Vernam Cipher <https://en.wikipedia.org/wiki/One-time_pad>`_, is a form of :class:`VigenereCipher` but utilizes a unqiue keyword (equal to the length of the plaintext) everytime when encoding.
        The cipher is not case-sensitive, so both plaintext and encoded text are converted to lowercase during processing.

        **Example**
        ---------------------------        
        .. code-block::python
        
           from ciphergeard.vernam import VernamCipher

           cipher = VernamCipher()

            plaintext = "ATTACK AT DAWN"

            keyword = cipher.generate_keyword(len(plaintext))
            # Output: nqfdetozrdxofi
            # Can vary as it is randomly generated.

            ciphertext, keyword = cipher.encode(plaintext=plaintext, keyword=keyword)
            # Output: njydgd zk aobv
            # Can vary as the keyword is randomly generated.

            plaintext = cipher.decode(ciphertext=ciphertext, keyword=keyword)
            # Output: attack at dawn
        """
        pass
    
    def generate_keyword(self, n: int):
        """
        Used to generate a random keyword of `n` length.

        ---------------------------

        :param n: The length of the keyword.
        :type n: int
        """
        return "".join(random.choices(string.ascii_lowercase, k=n))

    def encode(self, plaintext: str, keyword: str):
        """
        Used to encode the `plaintext`.

        ---------------------------

        :param plaintext: The plaintext to encode.
        :type plaintext: str

        :param keyword: The keyword to use.
        :type keyword: str
        
        ---------------------------

        :return: The encoded text.
        :rtype: str

        ---------------------------
        
        :raises VernamCipherError: Indicates an error while encoding.
        """
        plaintext = plaintext.lower().strip()

        if keyword and len(plaintext) != len(keyword):
            raise VernamCipherError(f"The length of plain text ({len(plaintext)}) should be equal to the length of the specified keyword ({len(keyword)}).")

        keyword = keyword or self.generate_keyword(len(plaintext))

        ciphertext = ""
        for p, k in zip(plaintext, keyword):
            if not p.isalpha():
                ciphertext += p
                continue
            ciphertext += chr(((ord(p) + ord(k) - 194) % 26) + 97)

        return ciphertext
    
    def decode(self, ciphertext: str, keyword: str):
        """
        Used to decode the `ciphertext`.

        ---------------------------

        :param ciphertext: The encoded text to decode.
        :type ciphertext: str

        :param keyword: The keyword to use.
        :type keyword: str

        ---------------------------

        :return: The decoded text.
        :rtype: str

        ---------------------------

        :raises VernamCipherError: Indicates an error while encoding.
        """
        ciphertext = ciphertext.lower().strip()

        if len(ciphertext) != len(keyword):
            raise VernamCipherError(f"The length of encoded text ({len(ciphertext)}) should be equal to the length of the specified keyword ({len(keyword)}).")

        plaintext = ""
        for e, k in zip(ciphertext, keyword):
            if not e.isalpha():
                plaintext += e
                continue
            
            plaintext += chr(((ord(e) - ord(k)) % 26) + 97)

        return plaintext