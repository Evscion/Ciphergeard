import string

class BifidCipherError(Exception):
    pass

class BifidCipher:
    def __init__(self, keyword: str, filler_char: str = "x") -> None:
        """
        The `Bifid Cipher <https://en.wikipedia.org/wiki/Bifid_cipher>`_, a cipher which combines the Polybius square with transposition, and uses fractionation to achieve diffusion. 
        The cipher is not case-sensitive, so both plaintext and encoded text are converted to lowercase during processing.

        All odd-length inputs will be suffixed by the specified `filler_char`. `'i'` and `'j'` share a combined position.

        ---------------------------

        :param keyword: The keyword to use while encoding.
        :type keyword: str

        :param filler_char: The filler character to suffix the text when of odd-length, defaults to `'x'`.
        :type filler_char: str

        ---------------------------

        **Example**
        ---------------------------
        .. code-block::python
        
           from ciphergeard.bifid import BifidCipher

           keyword = "SECRET"
           cipher = BifidCipher(keyword=keyword)

           plaintext = "ATTACK AT DAWN"

           ciphertext = cipher.encode(plaintext=plaintext)
           # Output: aecaby tv ktha

           plaintext = cipher.decode(ciphertext=ciphertext)
           # Output: attack at dawn
        """
        self.keyword = keyword.lower().strip()
        if not self.keyword:
            raise BifidCipherError('Please specify a proper keyword.')
        self.filler = filler_char
        self.square = self.generate_polybius_square()
        self.char_map = self.map_chars(self.square)

    def remove_dupes(self, l: list[str]):
        """
        Used to remove duplicates in a list by manually going through each and every element and checking if it already exists.
        `list(set(l))` could've been used here.

        ---------------------------

        :param l: The list to remove duplicates from.
        :type l: list[str]

        ---------------------------

        :return: The list from which all the duplicates are removed.
        :rtype: list[str]
        """
        fl = []
        for char in l:
            if not char in fl:
                fl.append(char)
        return fl

    def generate_polybius_square(self):
        """
        Used to generate a 5x5 `Polybius Square <https://en.wikipedia.org/wiki/Polybius_square>`_. 

        ---------------------------

        :return: The Polybius Square.
        :rtype: list
        """
        chars = self.remove_dupes(list(self.keyword + string.ascii_lowercase.replace('j', '')))
        return [chars[i:i+5] for i in range(0, 25, 5)]
    
    def map_chars(self, square = None):
        """
        Used to map the position of the English characters in `square` or `self.square`.

        ---------------------------

        :param square: A different square aside from `self.square`, defaults to `None`.
        :type square: list

        ---------------------------

        :return: A dict containing the mapped position of all the English characters in the square.
        :rtype: dict[tuple]
        """
        char_map = {}
        square = square or self.square
        for i, row in enumerate(square):
            for j, col in enumerate(row):
                char_map.update({col: (i, j)})
        return char_map
    
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
        plaintext: list[str] = list(plaintext.lower().strip().replace('j', 'i'))

        x, y = [], []
        z = {}

        i, offset = 0, 0
        while i < len(plaintext):
            c1, c2 = plaintext[i], (plaintext[i + 1] if i + 1 < len(plaintext) else self.filler)

            if not c1.isalpha():
                z.update({i + offset: c1})
                i += 1
                continue

            if not c2.isalpha():
                z.update({i + offset + 1: c2})
                plaintext.pop(i + 1)
                offset += 1
                continue

            p1, p2 = self.char_map[c1], self.char_map[c2]
            x.append((p1[0], p2[0]))
            y.append((p1[1], p2[1]))

            i += 2

        encoded = []
        for ele in x + y:
            encoded.append(self.square[ele[0]][ele[1]])

        for index, char in z.items():
            encoded.insert(index, char)

        ciphertext = "".join(encoded)
        if len(ciphertext) % 2 == 1 and ciphertext[-1] == self.filler:
            ciphertext = ciphertext[:-1]

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
        ciphertext: list[str] = list(ciphertext.lower().strip())

        if len(ciphertext) % 2 == 1:
            ciphertext += self.filler

        x = []
        z = {}
        for i, char in enumerate(ciphertext):
            if not char.isalpha():
                z.update({i: char})
            else:
                x.append(self.char_map[char])

        n = int(len(x) // 2)
        x, y = x[:n], x[n:]

        decoded = []
        for i in range(0, n):
            decoded.extend([self.square[x[i][0]][y[i][0]], self.square[x[i][1]][y[i][1]]])

        for index, char in z.items():
            decoded.insert(index, char)

        plaintext = "".join(decoded)
        if len(plaintext) % 2 == 1 and plaintext[-1] == self.filler:
            plaintext = plaintext[:-1]

        return plaintext