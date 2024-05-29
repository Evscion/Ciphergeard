import string
import random

class BaconianCipherError(Exception):
    pass

class BaconianCipher:
    def __init__(self, lookup_table: dict[str]) -> None:
        """
        The `Baconian Cipher <https://en.wikipedia.org/wiki/Bacon%27s_cipher>`_, a method of steganographic message encoding.
        The cipher is not case-sensitive, so both plaintext and encoded text are converted to lowercase during processing.

        A reverse dict of the `lookup_table` is generated for ease-of-access when decoding.

        ---------------------------

        :param lookup_table: The lookup table. Can be generated using the `generate_lookup_table` function.
        :type lookup_table: dict

        ---------------------------

        **Example**
        ---------------------------
        .. code-block::python
        
           from ciphergeard.baconion import BaconianCipher

           lookup_table = BaconianCipher.generate_lookup_table(multiple_char=True)
           cipher = BaconianCipher(lookup_table=lookup_table)

           plaintext = "ATTACK AT DAWN"

           ciphertext = cipher.encode(plaintext=plaintext)
           # Output: lwrxhdvjhidvjhilwrxhrtuumirhyk lwrxhdvjhi pmfjglwrxhcrawtnoeyi
           # Can vary as the `lookup_table` is randomly generated.

           plaintext = cipher.decode(ciphertext=ciphertext)
           # Output: attack at dawn
        """
        self.lookup_table = lookup_table
        self.rlookup_table = {val: key for key, val in self.lookup_table.items()}

    def generate_lookup_table(multiple_char: bool = False):
        """
        Used to generate a lookup table.

        ---------------------------

        :param multiple_char: If set to `True`, it will include the whole english alphabet for the cipher of a letter. Else, only 'a' & 'b', defaults to `False`.
        :type multiple_char: bool, optional

        ---------------------------

        :return: The lookup table.
        :rtype: dict
        """
        char_pool = string.ascii_lowercase if multiple_char else "ab"
        lookup_table = set()
        while len(lookup_table) < 26:
            sequence = "".join(random.choices(char_pool, k=5))
            lookup_table.add(sequence)
        return {letter: sequence for letter, sequence in zip(string.ascii_lowercase, lookup_table)}

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

        fstr = ""
        for char in plaintext:
            if not char.isalpha():
                fstr += char
                continue

            fstr += self.lookup_table[char]

        return fstr
    
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
        i = 0

        while i < len(ciphertext):
            sq = ciphertext[i : i + 5]

            if not sq[0].isalpha():
                for j, letter in enumerate(sq):
                    if letter.isalpha():
                        break
                    plaintext += letter
                else:
                    i += 5
                    continue

                i += j
                sq = ciphertext[i : i + 5]

            try:
                plaintext += self.rlookup_table[sq]
            except Exception:
                raise BaconianCipherError(f"Unable to decode invalid sequence - '{sq}' ({i})")
            
            i += 5

        return plaintext