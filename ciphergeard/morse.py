class MorseCode:
    def __init__(self) -> None:
        """
        `Morse code <https://en.wikipedia.org/wiki/Morse_code>`_ is a method used in telecommunication to encode text characters as standardized sequences of two different signal durations, called dots and dashes.
        The cipher is not case-sensitive, so both plaintext and encoded text are converted to lowercase during processing.

        **Example**
        ---------------------------
        .. code-block::python
        
           from ciphergeard.morse import MorseCode

           cipher = MorseCode()

           plaintext = "ATTACK AT DAWN"

           ciphertext = cipher.encode(plaintext=plaintext)
           # Output: .- - - .- -.-. -.-  .- -  -.. .- .-- -

           plaintext = cipher.decode(ciphertext=ciphertext)
           # Output: attack at dawn
        """
        self.char_map = {'a': '.-', 'b': '-...', 'c': '-.-.', 'd': '-..', 'e': '.', 'f': '..-.', 'g': '--.', 'h': '....', 'i': '..', 'j': '.---', 'k': '-.-', 'l': '.-..', 'm': '--', 'n': '-.', 'o': '---', 'p': '.--.', 'q': '--.-', 'r': '.-.', 's': '...', 't': '-', 'u': '..-', 'v': '...-', 'w': '.--', '*': '-..-', 'y': '-.--', 'z': '--..', '1': '.----', '2': '..---', '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.', '0': '-----', ',': '--..--', '?': '..--..', ':': '---...', '-': '-....-', '"': '.-..-.', '(': '-.--.', ')': '-.--.-', '=': '-...-', '.': '.-.-.-', ';': '-.-.-.', '/': '-..-.', "'": '.----.', '_': '..--.-', '+': '.-.-.', '@': '.--.-.'}
        self.rchar_map = {v: k for k, v in self.char_map.items()}

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
        for char in plaintext:
            if char == " ":
                ciphertext += "  "
                continue
            ciphertext += (" " if not ciphertext.endswith(' ') else "") + self.char_map.get(char, char)

        return ciphertext.strip()
    
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
        for char in ciphertext.split(' '):
            if char == "":
                plaintext += " "
                continue
            plaintext += self.rchar_map.get(char, char)

        return plaintext.strip()