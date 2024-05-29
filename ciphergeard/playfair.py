import string

class PlayfairCipherError(Exception):
    pass

class PlayfairCipher:
    def __init__(self, keyword: str, filler_char: str = 'x', table: list = None, char_map: dict = None):
        """
        The `Playfair cipher <https://en.wikipedia.org/wiki/Playfair_cipher>`_, a manual symmetric encryption technique and the first literal digram substitution cipher.
        The cipher is not case-sensitive, so both plaintext and encoded text are converted to lowercase during processing.

        All odd-length inputs will be suffixed by the specified `filler_char`. `'i'` and `'j'` share a combined position.

        ---------------------------

        :param keyword: The keyword to use while encoding.
        :type keyword: str

        :param filler_char: The filler character to suffix the text when of odd-length, defaults to `'x'`.
        :type filler_char: str

        :param table: The encoding table (if already generated), defaults to `None`.
        :type table: list, optional.

        :param char_map: The char map for the encoding table (if already generated), defaults to `None`.
        :type char_map: dict, optional.

        ---------------------------

        **Example**
        ---------------------------
        .. code-block::python
        
           from ciphergeard.playfair import PlayfairCipher

           keyword = "SECRET"
           cipher = PlayfairCipher(keyword=keyword)

           ciphertext = cipher.encode(plaintext=plaintext)
           # Output: gssgdp gs fbvo

           plaintext = cipher.decode(ciphertext=ciphertext)
           # Output: attack at dawn
        """
        self.keyword = keyword.lower().strip()
        if not self.keyword:
            raise PlayfairCipherError('Please specify a proper keyword.')
        self.filler = filler_char
        self.table = table or self.generate_table()
        self.char_map = char_map or self.map_chars()

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

    def generate_table(self):
        """
        Used to generate an encoding table for Playfair Cipher.

        ---------------------------

        :return: The generated encoding table.
        :rtype: list
        """
        chars = self.remove_dupes(self.keyword + string.ascii_letters.replace('j', ''))
        return [chars[i:i+5] for i in range(0, 25, 5)]
    
    def map_chars(self, table = None):
        """
        Used to map the position of the English characters in `table` or `self.table`.

        ---------------------------

        :param table: A different table aside from `self.table`, defaults to `None`.
        :type table: list

        ---------------------------

        :return: A dict containing the mapped position of all the English characters in the table.
        :rtype: dict[tuple]
        """
        char_map = {}
        table = table or self.table
        for i, row in enumerate(table):
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

        ciphertext = ""
        i = 0    
        exc2 = ""    
        while i < len(plaintext):
            c1, c2 = plaintext[i], (plaintext[i + 1] if i + 1 < len(plaintext) else self.filler)

            if not c1.isalpha():
                ciphertext += c1
                i += 1
                continue

            if not c2.isalpha():
                for j, char in enumerate(plaintext[i + 1:]):
                    if char.isalpha():
                        c2 = char
                        i += j
                        break
                    else:
                        exc2 += char
                else:
                    c2 = self.filler

            p1, p2 = self.char_map[c1], self.char_map[c2]

            if p1[0] == p2[0]: # Same row
                e1, e2 = self.table[p1[0]][p1[1] + 1 if p1[1] + 1 < 5 else 4 - p1[1]], self.table[p2[0]][p2[1] + 1 if p2[1] + 1 < 5 else 4 - p2[1]]

            elif p1[1] == p2[1]: # Same column
                e1, e2 = self.table[p1[0] + 1 if p1[0] + 1 < 5 else 4 - p1[0]][p1[1]], self.table[p2[0] + 1 if p2[0] + 1 < 5 else 4 - p2[0]][p2[1]]

            else: # Rectangle
                e1, e2 = self.table[p1[0]][p2[1]], self.table[p2[0]][p1[1]]

            ciphertext += e1 + exc2 + e2
            exc2 = ""
            i += 2

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
        ciphertext: list[str] = list(ciphertext.lower().strip().replace('j', 'i'))

        plaintext = ""
        i = 0
        exc2 = ""
        while i < len(ciphertext):
            c1, c2 = ciphertext[i], (ciphertext[i + 1] if i + 1 < len(ciphertext) else self.filler)

            if not c1.isalpha():
                plaintext += c1
                i += 1
                continue

            if not c2.isalpha():
                for j, char in enumerate(ciphertext[i + 1:]):
                    if char.isalpha():
                        c2 = char
                        i += j
                        break
                    else:
                        exc2 += char
                else:
                    c2 = self.filler

            p1, p2 = self.char_map[c1], self.char_map[c2]

            if p1[0] == p2[0]: # Same row
                d1, d2 = self.table[p1[0]][p1[1] - 1], self.table[p2[0]][p2[1] - 1]

            elif p1[1] == p2[1]: # Same column
                d1, d2 = self.table[p1[0] - 1][p1[1]], self.table[p2[0] - 1][p2[1]]

            else: # Rectangle
                d1, d2 = self.table[p1[0]][p2[1]], self.table[p2[0]][p1[1]]  

            plaintext += d1 + exc2 + d2
            exc2 = ""
            i += 2

        return plaintext