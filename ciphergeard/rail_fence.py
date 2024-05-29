class RailFenceCipher:
    def __init__(self, rails: int, placeholder: str = '#') -> None:
        """
        The `Rail Fence Cipher <https://en.wikipedia.org/wiki/Rail_fence_cipher>`_, is a classical type of transposition cipher. It derives its name from the manner in which encryption is performed, in analogy to a fence built with horizontal rails.
        The cipher is case-sensitive and can process uppercase and lowercase characters separately.

        ---------------------------

        :param rails: The number of rails to use.
        :type rails: int

        :param placeholder: The character to use as a placeholder when decoding, defaults to `'#'`.
        :type placeholder: str, optional

        ---------------------------

        **Example**
        ---------------------------
        .. code-block:: python
        
           from ciphergeard.rail_fence import RailFenceCipher

           cipher = RailFenceCipher(rails=2)

           plaintext = "Attack at Dawn"

           ciphertext = cipher.encode(plaintext=plaintext)
           # Output: Atc tDwtaka an

           plaintext = cipher.decode(ciphertext=ciphertext)
           # Output: Attack at Dawn
        """
        self.rails = rails
        self.placeholder = placeholder

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
        rail = [['' for _ in range(len(plaintext))] for _ in range(self.rails)]

        direction_down = False
        row, col = 0, 0
        
        for char in plaintext:
            rail[row][col] = char
            col += 1
            
            if row == 0 or row == self.rails - 1:
                direction_down = not direction_down
            
            row += 1 if direction_down else -1
        
        result = []
        for i in range(self.rails):
            for j in range(len(plaintext)):
                if rail[i][j] != '\n':
                    result.append(rail[i][j])
        return ''.join(result)
    
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
        rail = [['' for _ in range(len(ciphertext))] for _ in range(self.rails)]

        direction_down = False
        row, col = 0, 0

        for _ in range(len(ciphertext)):
            rail[row][col] = self.placeholder
            col += 1
            if row == 0 or row == self.rails - 1:
                direction_down = not direction_down
            row += 1 if direction_down else -1

        index = 0
        for i in range(self.rails):
            for j in range(len(ciphertext)):
                if rail[i][j] == self.placeholder and index < len(ciphertext):
                    rail[i][j] = ciphertext[index]
                    index += 1

        result = []
        row, col = 0, 0
        direction_down = False
        for _ in range(len(ciphertext)):
            result.append(rail[row][col])
            col += 1
            if row == 0 or row == self.rails - 1:
                direction_down = not direction_down
            row += 1 if direction_down else -1

        return ''.join(result)