import string
from ..vigenere import VigenereCipher

class GronsfeldVariantError(Exception):
    pass

class GronsfeldVariant(VigenereCipher):
    def __init__(self, key: int) -> None:
        """
        The `Vigenère Cipher's Gronsfeld Variant <https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher#Gronsfeld_cipher>`_.
        It inherits from the standard :class:`VigenereCipher` class and utilizes the algebraic method for encoding and decoding messages.
        The cipher is not case-sensitive, so both plaintext and encoded text are converted to lowercase during processing.

        Each digit in the specified key (int) must be between 1 and 26.

        ---------------------------

        :param keyword: The keyword to use while encoding/decoding.
        :type keyword: str

        ---------------------------

        **Example**
        ---------------------------
        .. code-block:: python
        
           from ciphergeard.vigenere.gronsfeld import GronsfeldVariant

           key = 69421
           cipher = GronsfeldVariant(key=key)

           plaintext = "ATTACK AT DAWN"

           ciphertext = cipher.encode(plaintext=plaintext)
           # Output: fbwbcp du iizo

           plaintext = cipher.decode(ciphertext=ciphertext)
           # Output: attack at dawn
        """
        super().__init__(self.__convertInt(key))

    def __convertInt(self, n: int):
        """
        Internal function to convert the `int` key to `str`.

        ---------------------------

        :param n: The `int` key.
        :type n: int

        ---------------------------

        :raises VigenereGronsfeldError: Indicates an error while converting the `int` to `str`.
        """
        fstr = ""
        for index, i in enumerate(str(n)):
            i = int(i)
            if i < 1 or i > 26:
                raise GronsfeldVariantError(f"`int` at index '{index}' must be between 1 and 26. - '{i}'")
            fstr += string.ascii_lowercase[i - 1]
        return fstr