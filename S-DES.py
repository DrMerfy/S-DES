# A configurable implementation of the S-DES encryption algorithm

from collections import deque


def merge_lists(l, r):
    """Merges the left and the right lists, return the simple concatenation"""

    new_list = l.copy()
    temp_r = r.copy()
    for i in range(len(temp_r)):
        new_list.append(temp_r.popleft())

    return new_list


class KeyGenerator:
    _sk = 0
    k1 = []
    k2 = []

    mask_p10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    mask_p8 = [6, 3, 7, 4, 8, 5, 10, 9]

    def add_secret_key(self, sk):
        """Takes as input a (base 2) number , 10-bit size, that is used as the secret key.
            This key is used to generate the two 8-bit keys required for the permutations."""

        # The P10 permutation
        p10 = []
        for i in range(10):
            p10.append(sk[self.mask_p10[i] - 1])

        # Split the permutation into 2 parts
        p10a = deque(p10[0:5])
        p10b = deque(p10[5:10])
        # Shift both by one
        p10a.append(p10a.popleft())
        p10b.append(p10b.popleft())
        # Merge into one
        p10 = merge_lists(p10a, p10b)

        # The first P8 permutation, creating the key1
        for i in range(8):
            self.k1.append(p10[self.mask_p8[i] - 1])

        # The second P8 permutation
        # Shift left, two times, the previous 2 lists
        p10a.append(p10a.popleft())
        p10a.append(p10a.popleft())
        p10b.append(p10b.popleft())
        p10b.append(p10b.popleft())

        p10 = merge_lists(p10a, p10b)
        # Create the key2
        for i in range(8):
            self.k2.append(p10[self.mask_p8[i] - 1])



keygen = KeyGenerator()

keygen.add_secret_key('1010000010')
