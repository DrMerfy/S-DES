# A configurable implementation of the S-DES encryption algorithm

from collections import deque


def bin_to_int(n1, n2):
    """Takes two binary numbers, concatenates the second to the first, and returns the int representation"""
    return int(n1)*2 + int(n2)


def merge_lists(l, r):
    """Merges the left and the right lists, returns the simple concatenation"""

    new_list = l.copy()
    temp_r = r.copy()
    for i in range(len(temp_r)):
        new_list.append(temp_r.popleft())

    return new_list


def xor(n1, n2):
    """XORs two numbers"""
    return (int(n1) + int(n2)) % 2

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


class SDES:
    mask_IP = [2, 6, 3, 1, 4, 8, 5, 7]
    mask_IP_inv = [4, 1, 3, 5, 7, 2, 8, 6]
    mask_e_p = [4, 1, 2, 3, 2, 3, 4, 1]
    mask_p4 = [2, 4, 3, 1]

    S0 = [[1, 0, 3, 2],
          [3, 2, 1, 0],
          [0, 2, 1, 3],
          [3, 1, 3, 2]]

    S1 = [[0, 1, 2, 3],
          [2, 0, 1, 3],
          [3, 0, 1, 0],
          [2, 1, 0, 3]]

    _k1 = 0
    _k2 = 0

    @staticmethod
    def _crypt_function(key, m):
        """Implements the cryptographic function of the encryption algorithm (aka f_k)"""
        # Expansion
        feed0 = []
        for i in range(4):
            feed0.append(xor(m[SDES.mask_e_p[i] - 1], key[i]))

        # Permutation
        feed1 = []
        for i in range(4, 8):
            feed1.append(xor(m[SDES.mask_e_p[i] - 1], key[i]))

        # print("EP: ", feed0, feed1)
        # Take the corresponding numbers from the box
        s0 = bin(SDES.S0[bin_to_int(feed0[0], feed0[3])][bin_to_int(feed0[1], feed0[2])])[2:]
        s1 = bin(SDES.S1[bin_to_int(feed1[0], feed1[3])][bin_to_int(feed1[1], feed1[2])])[2:]

        # print("S-Boxes:", s0, s1)

        # Convert to 2-bit size array
        if len(s0) == 1:
            temp = s0
            s0 = ['0', temp]

        if len(s1) == 1:
            temp = s1
            s1 = ['0', temp]

        # print("S-Boxes: [Converted]", s0, s1)

        # Merge the result
        res = [s0[0], s0[1], s1[0], s1[1]]
        return res

    def _cryptographic_method(self, l, r, key):
        """Implements the generic cryptographic mechanism"""

        # f_k1(R, sk)
        temp = SDES._crypt_function(key, r)
        # The P4 permutation
        p4 = []
        for i in range(4):
            p4.append(temp[self.mask_p4[i] - 1])

        crypt = []
        for i in range(4):
            crypt.append(xor(l[i], p4[i]))

        # Append the right part
        for i in range(4):
            crypt.append(r[i])

        return crypt

    def add_keys(self, k1, k2):
        """Adds the keys associated with a S-DES session"""
        self._k1 = k1
        self._k2 = k2

    def encrypt_message(self, m):
        """Encrypts the given (8-bit) message using the keys of the session"""

        # Initial Permutation
        ip = []
        for i in range(8):
            ip.append(m[self.mask_IP[i] - 1])
        # print("Initial Permutation: ", ip)

        crypt_k1 = self._cryptographic_method(ip[0:4], ip[4:8], self._k1)
        # print("Key1: ", crypt_k1)
        crypt_k2 = self._cryptographic_method(crypt_k1[4:8], crypt_k1[0:4], self._k2)

        # Reverse Permutation
        ip_inv = []
        for i in range(8):
            ip_inv.append(crypt_k2[self.mask_IP_inv[i] - 1])
        return ip_inv

    def decrypt_message(self, c):
        """Decrypts the given (8-bit) cipher text using the keys of the session"""

        # Initial Permutation
        ip = []
        for i in range(8):
            ip.append(c[self.mask_IP[i] - 1])

        crypt_k2 = self._cryptographic_method(ip[0:4], ip[4:8], self._k2)
        crypt_k1 = self._cryptographic_method(crypt_k2[4:8], crypt_k2[0:4], self._k1)

        # Reverse Permutation
        ip_inv = []
        for i in range(8):
            ip_inv.append(crypt_k1[self.mask_IP_inv[i] - 1])
        return ip_inv


# Create the keys
keygen = KeyGenerator()

keygen.add_secret_key('1100011110')
print('Created keys:', keygen.k1, keygen.k2)

# Initialization
sdes = SDES()
sdes.add_keys(keygen.k1, keygen.k2)
# sdes.add_keys('10100100', '01000011')

message = '00101000'
print("Message: ", message)

# Encryption
cipher_text = sdes.encrypt_message(message)
print('Cipher text: ', cipher_text)

# Decryption
plain_text = sdes.decrypt_message(cipher_text)
print('Decrypted text: ', plain_text)



