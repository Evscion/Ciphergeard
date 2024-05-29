import math
from ..vigenere import VigenereCipher

class RunningKeyVariant(VigenereCipher):
    def __init__(self, keywords: list[str], max_lcm: int = None) -> None:
        """
        The `Vigenère Cipher's Running Key Variant <https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher#Running_key>`_.
        It inherits from the standard :class:`VigenereCipher` class and utilizes the algebraic method for encoding and decoding messages.
        The cipher is not case-sensitive, so both plaintext and encoded text are converted to lowercase during processing.

        Unlike the standard Vigenère cipher that uses a single keyword, the Running Key variant employs a series of keywords.
        The keywords are standardized by either repeated or truncated achieved by calculating the LCM of their lengths.
        The keywords are encoded by each other till a final keyword is obtained.

        ---------------------------

        :param keywords: The keywords to use.
        :type keywords: list[str]

        :param max_lcm: The maximum LCM value and can be any natural number, defaults to None.
        :type max_lcm: int

        ---------------------------

        :raises ValueError: Indicates that there was an error during initialization.

        ---------------------------

        **Example**
        ---------------------------
        .. code-block:: python
        
           from ciphergeard.vigenere.running_key import RunningKeyVariant

           keywords = ["CATS", "ARE", "CUTER", "THAN", "DOGS"]
           cipher = RunningKeyVariant(keywords=keywords)

           plaintext = "ATTACK AT DAWN"

           ciphertext = cipher.encode(plaintext=plaintext)
           # Output: gvfkim kz pkcp

           plaintext = cipher.decode(ciphertext=ciphertext)
           # Output: attack at dawn

        """
        if max_lcm and max_lcm <= 0:
            raise ValueError('`max_lcm` must be a natural number, i.e., > 0.')
    
        lcm = math.lcm(*(len(keyword) for keyword in keywords))
        if max_lcm:
            lcm = min(max_lcm, lcm)

        lcmstr = "a" * lcm

        self.keyword = keywords.pop(0).lower().strip()
        fkeyword = self.match_keyword_length(plaintext=lcmstr)

        for keyword in keywords:
            self.keyword = keyword.lower().strip()
            mkeyword = self.match_keyword_length(plaintext=lcmstr)
            fkeyword = self.encode(plaintext=mkeyword)

        super().__init__(fkeyword)
