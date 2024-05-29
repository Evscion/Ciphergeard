from ..vigenere import VigenereCipher

class BeaufortVariantError(Exception):
    pass

class BeaufortVariant(VigenereCipher):
    def __init__(self, keyword: str) -> None:
        """
        This class implements the `Vigenère Cipher's Beaufort Variant <https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher#Variant_Beaufort>`_.
        It inherits from the standard :class:`VigenereCipher` class and utilizes the algebraic method for encoding and decoding messages.
        The cipher is not case-sensitive, so both plaintext and encoded text are converted to lowercase during processing.

        The Beaufort variant works differently. It first decodes the previous encoded character using the keyword character.
        Then, it uses this decoded character to determine the shift for the next character in the plaintext during the encoding process.

        ---------------------------

        :param keyword: The keyword to use while encoding/decoding.
        :type keyword: str

        ---------------------------        

        **Example**
        ---------------------------    
        .. code-block:: python

           from ciphergeard.vigenere.beaufort import BeaufortVariant

           keyword = "SECRET"
           cipher = BeaufortVariant(keyword=keyword)

           plaintext = "ATTACK AT DAWN"

           ciphertext = cipher.encode(plaintext=plaintext)
           # Output: iprjyr wr zhej

           plaintext = cipher.decode(ciphertext=ciphertext)
           # Output: attack at dawn
        """
        super().__init__(keyword=keyword)

    def encode(self, plaintext: str):
        """
        Used to encode the `plaintext`.

        ---------------------------

        :param plaintext: The text to encode.
        :type plaintext: str

        ---------------------------

        :return: The encoded text.
        :rtype: str
        """
        plaintext = plaintext.lower().strip()
        ciphertext = ""

        keyword = self.match_keyword_length(plaintext) if len(self.keyword) != len(plaintext) else self.keyword
        
        for i, j in zip(plaintext, keyword, strict=True):
            if not i.isalpha():
                ciphertext += i
                continue
            ciphertext += chr(((self.get_index(i) - self.get_index(j)) % 26) + 97)

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
        ciphertext = ciphertext.lower().strip()
        plaintext = ""

        keyword = self.match_keyword_length(ciphertext) if len(self.keyword) != len(ciphertext) else self.keyword
        
        for i, j in zip(ciphertext, keyword, strict=True):
            if not i.isalpha():
                plaintext += i
                continue
            plaintext += chr(((self.get_index(i) + self.get_index(j)) % 26) + 97)
            continue

        return plaintext