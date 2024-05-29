from .caesar import CaesarCipher

class ROT13Cipher(CaesarCipher):
    def __init__(self, case_sensitive: bool = False) -> None:
        """
        The `ROT13 Cipher <https://en.wikipedia.org/wiki/ROT13>`_, a simple letter substitution cipher that replaces a letter with the 13th letter after it.
        It is a special case of the :class:`CaesarCipher` with the offset set to `13`.

        ---------------------------

        :param case_sensitive: Indicates whether the cipher should be case-sensitive or not, defaults to `False`.
        :type case_sensitive: bool, optional.

        ---------------------------

        **Example**
        ---------------------------
        .. code-block:: python

           from ciphergeard.rot13 import ROT13Cipher

           cipher = ROT13Cipher(case_sensitive=True)

           plaintext = "ATTACK AT DAWN"

           ciphertext = cipher.encode(plaintext=plaintext)
           # Output: NGGNPX NG QNJA

           plaintext = cipher.decode(ciphertext=ciphertext)
           # Output: ATTACK AT DAWN
        """
        super().__init__(offset=13, case_sensitive=case_sensitive)