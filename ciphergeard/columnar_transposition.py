class ColumnarTranspositionCipherError(Exception):
    pass

class ColumnarTranspositionCipher:
    def __init__(self, keyword: str) -> None:
        """
        The `Columnar Transposition Cipher <https://en.wikipedia.org/wiki/Transposition_cipher#Columnar_transposition>`_ in which the message is written out in rows of a fixed length, and then read out again column by column.
        The cipher is case-sensitive and can process uppercase and lowercase characters separately.

        ---------------------------

        :param keyword: The keyword to use while encoding.
        :type keyword: str

        ---------------------------

        **Example**
        ---------------------------
        .. code-block::python
        
           from ciphergeard.columnar_transposition import ColumnarTranspositionCipher

           keyword = "SECRET"
           cipher = ColumnarTranspositionCipher(keyword=keyword)

           plaintext = "Attack at Dawn"

           ciphertext = cipher.encode(plaintext=plaintext)
           # Output: tt tancD a  A wka

           plaintext = cipher.decode(ciphertext=ciphertext)
           # Output: Attack at Dawn
        """
        self.keyword = keyword.strip()
        if not self.keyword:
            raise ColumnarTranspositionCipherError('Please specify a proper keyword.')

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
        plaintext = plaintext.strip()

        num_cols = len(self.keyword)
        num_rows = -(-len(plaintext) // num_cols)
        
        grid = ['' for _ in range(num_rows)]
        
        for i, char in enumerate(plaintext):
            row = i // num_cols
            grid[row] += char
        
        if len(grid[-1]) < num_cols:
            grid[-1] += ' ' * (num_cols - len(grid[-1]))
        
        ciphertext = ''
        for col_index in sorted(range(num_cols), key=lambda x: self.keyword[x]):
            for row in grid:
                ciphertext += row[col_index]
        
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
        num_cols = len(self.keyword)
        num_rows = -(-len(ciphertext) // num_cols)

        col_order = sorted(range(num_cols), key=lambda x: self.keyword[x])

        num_full_cols = len(ciphertext) % num_cols
        num_full_rows = len(ciphertext) // num_cols

        col_lengths = [num_full_rows + 1 if i < num_full_cols else num_full_rows for i in range(num_cols)]

        col_texts = []
        start = 0
        for length in col_lengths:
            col_texts.append(ciphertext[start:start + length])
            start += length

        grid = ['' for _ in range(num_rows)]

        for col_index, text in zip(col_order, col_texts):
            for row_index, char in enumerate(text):
                if len(grid[row_index]) < num_cols:
                    grid[row_index] += ' ' * (num_cols - len(grid[row_index]))
                grid[row_index] = grid[row_index][:col_index] + char + grid[row_index][col_index + 1:]

        plaintext = ''.join(grid).rstrip()

        return plaintext
        