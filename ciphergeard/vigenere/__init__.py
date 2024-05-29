class VigenereCipherError(Exception):
    pass

class VigenereCipher:
    def __init__(self, keyword: str) -> None:
        """
        This class implements the `Vigenère Cipher <https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher>`_, a classic polyalphabetic substitution cipher.
        It utilizes the algebraic method for encoding and decoding messages.
        The cipher is not case-sensitive, so both plaintext and encoded text are converted to lowercase during processing.

        ---------------------------
        
        :param keyword: The keyword to use while encoding/decoding.
        :type keyword: str

        ---------------------------

        **Example**
        ---------------------------
        .. code-block:: python
        
           from ciphergeard.vigenere import VigenereCipher

           keyword = "SECRET"
           cipher = VigenereCipher(keyword=keyword)

           plaintext = "ATTACK AT DAWN"

           ciphertext = cipher.encode(plaintext=plaintext)
           # Output: sxvrgd ev htor

           plaintext = cipher.decode(ciphertext=ciphertext)
           # Output: attack at dawn
        """
        self.keyword = keyword.lower().strip()
        if not self.keyword:
            raise VigenereCipherError('Please specify a proper keyword.')

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

        keyword = self.match_keyword_length(plaintext) if len(self.keyword) != len(plaintext) else self.keyword
        
        for i, j in zip(plaintext, keyword, strict=True):
            if not i.isalpha():
                ciphertext += i
                continue
            ciphertext += chr(((self.get_index(i) + self.get_index(j)) % 26) + 97)
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
        ciphertext = ciphertext.lower().strip()
        plaintext = ""

        keyword = self.match_keyword_length(ciphertext) if len(self.keyword) != len(ciphertext) else self.keyword
        
        for i, j in zip(ciphertext, keyword, strict=True):
            if not i.isalpha():
                plaintext += i
                continue
            plaintext += chr(((self.get_index(i) - self.get_index(j)) % 26) + 97)

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
        """
        return ord(letter) - 97

    def match_keyword_length(self, plaintext: str):
        """
        Used to format the `self.keyword` to match the length of the `plaintext`.

        ---------------------------

        :param plaintext: The plaintext to encode.
        :type plaintext: str

        ---------------------------

        :return: The formatted keyword.
        :rtype: str
        """
        keyword_length = len(self.keyword)
        plaintext_length = len(plaintext.lower().strip())

        if len(self.keyword) == len(plaintext):
            return self.keyword
        
        repetitions = (plaintext_length // keyword_length) + 1
        return (self.keyword * repetitions)[:plaintext_length]