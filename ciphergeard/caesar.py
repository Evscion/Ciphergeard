from .affine import AffineCipher

class CaesarCipherError(Exception):
    pass

class CaesarCipher(AffineCipher):
    def __init__(self, offset: int, case_sensitive: bool = False) -> None:
        """
        The `Caesar Cipher <https://en.wikipedia.org/wiki/Caesar_cipher>`_, one of the simplest and most widely known substitution cipher.
        It is based on :class:`AffineCipher`.
        The cipher is by default insensitive to case, but can be specified to be case-sensitive. If insensitive, all the characters will be lowercased before processing.

        ---------------------------

        :param offset: The offset.
        :type offset: int

        :param case_sensitive: Indicates whether the cipher should be case-sensitive or not, defaults to `False`.
        :type case_sensitive: bool, optional.

        ---------------------------

        **Example**
        ---------------------------
        .. code-block:: python

           from ciphergeard.caesar import CaesarCipher

           offset = 4
           cipher = CaesarCipher(offset=offset, case_sensitive=True)

           plaintext = "ATTACK AT DAWN"

           ciphertext = cipher.encode(plaintext=plaintext)
           # Output: EXXEGO EX HEAR

           plaintext = cipher.decode(ciphertext=ciphertext)
           # Output: ATTACK AT DAWN
        """
        super().__init__(a=1, b=offset, case_sensitive=case_sensitive)