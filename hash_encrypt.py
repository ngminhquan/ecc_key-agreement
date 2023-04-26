import struct
import sys
from collections import deque
import numpy as np

import struct
import sys


K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

def hash_function(data: bytearray) -> bytearray:

    if isinstance(data, str):
        data = bytearray(data, 'utf-8')
    elif isinstance(data, bytes):
        data = bytearray(data)
    elif not isinstance(data, bytearray):
        raise TypeError
    
    length = len(data) * 8 
    data.append(0x80)
    while (len(data) * 8 + 64) % 512 != 0:
        data.append(0x00)

    data += length.to_bytes(8, 'big') 

    assert (len(data) * 8) % 512 == 0, "Padding did not complete properly!"

    blocks = [] 
    for i in range(0, len(data), 64): 
        blocks.append(data[i:i+64])

    h0 = 0x6a09e667
    h1 = 0xbb67ae85
    h2 = 0x3c6ef372
    h3 = 0xa54ff53a
    h5 = 0x9b05688c
    h4 = 0x510e527f
    h6 = 0x1f83d9ab
    h7 = 0x5be0cd19

    for data_block in blocks:
        data_schedule = []
        for t in range(0, 64):
            if t <= 15:
                data_schedule.append(bytes(data_block[t*4:(t*4)+4]))
            else:
                term1 = _sigma1(int.from_bytes(data_schedule[t-2], 'big'))
                term2 = int.from_bytes(data_schedule[t-7], 'big')
                term3 = _sigma0(int.from_bytes(data_schedule[t-15], 'big'))
                term4 = int.from_bytes(data_schedule[t-16], 'big')
                schedule = ((term1 + term2 + term3 + term4) % 2**32).to_bytes(4, 'big')
                data_schedule.append(schedule)

        assert len(data_schedule) == 64

        
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7

        
        for t in range(64):
            t1 = ((h + _capsigma1(e) + _ch(e, f, g) + K[t] +
                   int.from_bytes(data_schedule[t], 'big')) % 2**32)

            t2 = (_capsigma0(a) + _maj(a, b, c)) % 2**32

            h = g
            g = f
            f = e
            e = (d + t1) % 2**32
            d = c
            c = b
            b = a
            a = (t1 + t2) % 2**32

        
        h0 = (h0 + a) % 2**32
        h1 = (h1 + b) % 2**32
        h2 = (h2 + c) % 2**32
        h3 = (h3 + d) % 2**32
        h4 = (h4 + e) % 2**32
        h5 = (h5 + f) % 2**32
        h6 = (h6 + g) % 2**32
        h7 = (h7 + h) % 2**32

    return ((h0).to_bytes(4, 'big') + (h1).to_bytes(4, 'big') +
            (h2).to_bytes(4, 'big') + (h3).to_bytes(4, 'big') +
            (h4).to_bytes(4, 'big') + (h5).to_bytes(4, 'big') +
            (h6).to_bytes(4, 'big') + (h7).to_bytes(4, 'big'))

def _sigma0(num: int):
    
    num = (ROTR(num, 7) ^
           ROTR(num, 18) ^
           (num >> 3))
    return num

def _sigma1(num: int):
    
    num = (ROTR(num, 17) ^
           ROTR(num, 19) ^
           (num >> 10))
    return num

def _capsigma0(num: int):
    
    num = (ROTR(num, 2) ^
           ROTR(num, 13) ^
           ROTR(num, 22))
    return num

def _capsigma1(num: int):
    
    num = (ROTR(num, 6) ^
           ROTR(num, 11) ^
           ROTR(num, 25))
    return num

def _ch(x: int, y: int, z: int):
    
    return (x & y) ^ (~x & z)

def _maj(x: int, y: int, z: int):
    
    return (x & y) ^ (x & z) ^ (y & z)

def ROTR(num: int, shift: int, size: int = 32):
    
    return (num >> shift) | (num << size - shift)



'''
data = b'12345'
if __name__ == "__main__":
    print(hash_function(data).hex())
'''


""" PRESENT block cipher implementation

USAGE EXAMPLE:
---------------
Importing:
-----------
>>> from pypresent import Present

Encrypting with a 80-bit key:
------------------------------
>>>key = b'10 bytes--'
>>>plain = b'minhquan'
>>>cipher = Present(key)
>>>encrypted = cipher.encrypt(plain)
b'8K\xf0\x80\xe4\x0e\xf8G'

>>>decrypted = cipher.decrypt(encrypted)
b'minhquan'

Encrypting with a 128-bit key:
-------------------------------
>>> key = b'16 bytes length.'
>>> plain = b'minhquan'
>>> cipher = Present(key)
>>> encrypted = cipher.encrypt(plain)
b'\xf4\x8a\xfdQ\xca\xd7Up'

>>> decrypted = cipher.decrypt(encrypted)
b'minhquan'

"""
class Present:
        def __init__(self,key,rounds=32):
                """Create a PRESENT cipher object

                key:    the key as a 128-bit or 80-bit rawstring
                rounds: the number of rounds as an integer, 32 by default
                """
                self.rounds = rounds
                if len(key) * 8 == 80:
                        self.roundkeys = generateRoundkeys80(bytes_to_long(key),self.rounds)
                elif len(key) * 8 == 128:
                        self.roundkeys = generateRoundkeys128(bytes_to_long(key),self.rounds)
                else:
                        raise ValueError /'Key must be a 128-bit or 80-bit rawstring'

        def encrypt(self,block):
                """Encrypt 1 block (8 bytes)

                Input:  plaintext block as raw string
                Output: ciphertext block as raw string
                """
                state = bytes_to_long(block)
                for i in range(self.rounds - 1):
                        state = addRoundKey(state,self.roundkeys[i])
                        state = sBoxLayer(state)
                        state = pLayer(state)
                cipher = addRoundKey(state,self.roundkeys[-1])
                return long_to_bytes(cipher,8)

        def decrypt(self,block):
                """Decrypt 1 block (8 bytes)

                Input:  ciphertext block as raw string
                Output: plaintext block as raw string
                """
                state = bytes_to_long(block)
                for i in range(self.rounds - 1):
                        state = addRoundKey(state,self.roundkeys[-i-1])
                        state = pLayer_dec(state)
                        state = sBoxLayer_dec(state)
                decipher = addRoundKey(state,self.roundkeys[0])
                return long_to_bytes(decipher,8)

        def get_block_size(self):
                return 8

#        0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f
Sbox= [0xc,0x5,0x6,0xb,0x9,0x0,0xa,0xd,0x3,0xe,0xf,0x8,0x4,0x7,0x1,0x2]
Sbox_inv = [Sbox.index(x) for x in range(16)]
PBox = [0,16,32,48,1,17,33,49,2,18,34,50,3,19,35,51,
        4,20,36,52,5,21,37,53,6,22,38,54,7,23,39,55,
        8,24,40,56,9,25,41,57,10,26,42,58,11,27,43,59,
        12,28,44,60,13,29,45,61,14,30,46,62,15,31,47,63]
PBox_inv = [PBox.index(x) for x in range(64)]

def generateRoundkeys80(key,rounds):
        """Generate the roundkeys for a 80-bit key

        Input:
                key:    the key as a 80-bit integer
                rounds: the number of rounds as an integer
        Output: list of 64-bit roundkeys as integers"""
        roundkeys = []
        for i in range(1, rounds + 1): # (K1 ... K32)
                # rawkey: used in comments to show what happens at bitlevel
                # rawKey[0:64]
                roundkeys.append(key >>16)
                #1. Shift
                #rawKey[19:len(rawKey)]+rawKey[0:19]
                key = ((key & (2**19-1)) << 61) + (key >> 19)
                #2. SBox
                #rawKey[76:80] = S(rawKey[76:80])
                key = (Sbox[key >> 76] << 76)+(key & (2**76-1))
                #3. Salt
                #rawKey[15:20] ^ i
                key ^= i << 15
        return roundkeys

def generateRoundkeys128(key,rounds):
        """Generate the roundkeys for a 128-bit key

        Input:
                key:    the key as a 128-bit integer
                rounds: the number of rounds as an integer
        Output: list of 64-bit roundkeys as integers"""
        roundkeys = []
        for i in range(1, rounds + 1): # (K1 ... K32)
                # rawkey: used in comments to show what happens at bitlevel
                roundkeys.append(key >>64)
                #1. Shift
                key = ((key & (2**67-1)) << 61) + (key >> 67)
                #2. SBox
                key = (Sbox[key >> 124] << 124)+(Sbox[(key >> 120) & 0xF] << 120)+(key & (2**120-1))
                #3. Salt
                #rawKey[62:67] ^ i
                key ^= i << 62
        return roundkeys

def addRoundKey(state,roundkey):
        return state ^ roundkey

def sBoxLayer(state):
        """SBox function for encryption

        Input:  64-bit integer
        Output: 64-bit integer"""

        output = 0
        for i in range(16):
                output += Sbox[( state >> (i*4)) & 0xF] << (i*4)
        return output

def sBoxLayer_dec(state):
        """Inverse SBox function for decryption

        Input:  64-bit integer
        Output: 64-bit integer"""
        output = 0
        for i in range(16):
                output += Sbox_inv[( state >> (i*4)) & 0xF] << (i*4)
        return output

def pLayer(state):
        """Permutation layer for encryption

        Input:  64-bit integer
        Output: 64-bit integer"""
        output = 0
        for i in range(64):
                output += ((state >> i) & 0x01) << PBox[i]
        return output

def pLayer_dec(state):
        """Permutation layer for decryption

        Input:  64-bit integer
        Output: 64-bit integer"""
        output = 0
        for i in range(64):
                output += ((state >> i) & 0x01) << PBox_inv[i]
        return output

#convert bytes -> long and long -> bytes
def long_to_bytes(n, blocksize=0):

    if n < 0 or blocksize < 0:
        raise ValueError("Values must be non-negative")

    result = []
    pack = struct.pack

    # Fill the first block independently from the value of n
    bsr = blocksize
    while bsr >= 8:
        result.insert(0, pack('>Q', n & 0xFFFFFFFFFFFFFFFF))
        n = n >> 64
        bsr -= 8

    while bsr >= 4:
        result.insert(0, pack('>I', n & 0xFFFFFFFF))
        n = n >> 32
        bsr -= 4

    while bsr > 0:
        result.insert(0, pack('>B', n & 0xFF))
        n = n >> 8
        bsr -= 1

    if n == 0:
        if len(result) == 0:
            bresult = b'\x00'
        else:
            bresult = b''.join(result)
    else:
        # The encoded number exceeds the block size
        while n > 0:
            result.insert(0, pack('>Q', n & 0xFFFFFFFFFFFFFFFF))
            n = n >> 64
        result[0] = result[0].lstrip(b'\x00')
        bresult = b''.join(result)
        # bresult has minimum length here
        if blocksize > 0:
            target_len = ((len(bresult) - 1) // blocksize + 1) * blocksize
            bresult = b'\x00' * (target_len - len(bresult)) + bresult

    return bresult


def bytes_to_long(s):
    """Convert a byte string to a long integer (big endian).

    In Python 3.2+, use the native method instead::

        >>> int.from_bytes(s, 'big')

    For instance::

        >>> int.from_bytes(b'\x00P', 'big')
        80

    This is (essentially) the inverse of :func:`long_to_bytes`.
    """
    acc = 0

    unpack = struct.unpack

    # Up to Python 2.7.4, struct.unpack can't work with bytearrays nor
    # memoryviews
    if sys.version_info[0:3] < (2, 7, 4):
        if isinstance(s, bytearray):
            s = bytes(s)
        elif isinstance(s, memoryview):
            s = s.tobytes()

    length = len(s)
    if length % 4:
        extra = (4 - length % 4)
        s = b'\x00' * extra + s
        length = length + extra
    for i in range(0, length, 4):
        acc = (acc << 32) + unpack('>I', s[i:i+4])[0]
    return acc

#photon lightweight hash function
'''
#AES-Permutation algorithm 

fieldmult2 = [[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
              [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
              [0, 2, 4, 6, 8, 10, 12, 14, 3, 1, 7, 5, 11, 9, 15, 13],
              [0, 3, 6, 5, 12, 15, 10, 9, 11, 8, 13, 14, 7, 4, 1, 2],
              [0, 4, 8, 12, 3, 7, 11, 15, 6, 2, 14, 10, 5, 1, 13, 9],
              [0, 5, 10, 15, 7, 2, 13, 8, 14, 11, 4, 1, 9, 12, 3, 6],
              [0, 6, 12, 10, 11, 13, 7, 1, 5, 3, 9, 15, 14, 8, 2, 4],
              [0, 7, 14, 9, 15, 8, 1, 6, 13, 10, 3, 4, 2, 5, 12, 11],
              [0, 8, 3, 11, 6, 14, 5, 13, 12, 4, 15, 7, 10, 2, 9, 1],
              [0, 9, 1, 8, 2, 11, 3, 10, 4, 13, 5, 12, 6, 15, 7, 14],
              [0, 10, 7, 13, 14, 4, 9, 3, 15, 5, 8, 2, 1, 11, 6, 12],
              [0, 11, 5, 14, 10, 1, 15, 4, 7, 12, 2, 9, 13, 6, 8, 3],
              [0, 12, 11, 7, 5, 9, 14, 2, 10, 6, 1, 13, 15, 3, 4, 8],
              [0, 13, 9, 4, 1, 12, 8, 5, 2, 15, 11, 6, 3, 14, 10, 7],
              [0, 14, 15, 1, 13, 3, 2, 12, 9, 7, 6, 8, 4, 10, 11, 5],
              [0, 15, 13, 2, 9, 6, 4, 11, 1, 14, 12, 3, 8, 7, 5, 10]]

class permutation:
    
    def __init__(self, input_hash,round_num=12):
        
        self.input = input_hash
        self.input_len = len(input_hash)
        self.round_num = round_num
        self.each_round_value = []
    
    def rc(self,v):
        if v == 1:
            return [1, 0, 2, 7, 5]
        elif v == 2:
            return [3, 2, 0, 5, 7]
        elif v == 3:
            return [7, 6, 4, 1, 3]
        elif v == 4:
            return [14, 15, 13, 8, 10]
        elif v == 5:
            return [13, 12, 14, 11, 9]
        elif v == 6:
            return [11, 10, 8, 13, 15]
        elif v == 7:
            return [6, 7, 5, 0, 2]
        elif v == 8:
            return [12, 13, 15, 10, 8]
        elif v == 9:
            return [9, 8, 10, 15, 13]
        elif v == 10:
            return [2, 3, 1, 4, 6]
        elif v == 11:
            return [5, 4, 6, 3, 1]
        elif v == 12:
            return [10, 11, 9, 12, 14]
    
    def shift_row(self):
        
        result_shiftrow = []
        for row in range(self.input_len):
            item = deque(self.input[row])
            item.rotate(-row)
            result_shiftrow.append(list(item))
        
        self.input = result_shiftrow
        
        return result_shiftrow
        
    def subcell(self):

        sbox = [0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2]
        result_subcell = self.input
        for i in range(0, self.input_len):
            for j in range(0, self.input_len):
                result_subcell[i][j] = sbox[int(self.input[i][j])]
        
        self.input = result_subcell
        
        return result_subcell
                
    def addconstant(self,v):
   
        result_addconstant = self.input

        for i in range(0, self.input_len):
            result_addconstant[i][0] = self.input[i][0] ^ self.rc(v)[i]
        
        self.input = result_addconstant
        
        return result_addconstant
        
    
    def mixcolumn(self):

        A_t = [[1, 2, 9, 9, 2],
               [2, 5, 3, 8, 13],
               [13, 11, 10, 12, 1],
               [1, 15, 2, 3, 14],
               [14, 14, 8, 5, 12]]

        #irreducible polynomial  = x^4+x+1 : 10011

        result_mixcolumn = [[0 for x in range(self.input_len)] for x in range(self.input_len)]
        xor_sum = 0
        for i in range(0, self.input_len):
            for j in range(0, self.input_len):
                for k in range(0, self.input_len):
                    xor_sum = xor_sum ^ fieldmult2[A_t[i][k]][self.input[k][j]]
                result_mixcolumn[i][j] = xor_sum
                xor_sum = 0
        
        self.input = result_mixcolumn
        
        return result_mixcolumn
    
    def get_each_round(self):
        
        return self.each_round_value
               
            
    def permutation_result(self):
        
        for i in range(self.round_num):
            
            self.addconstant(i+1)
            self.subcell()
            self.shift_row()
            self.mixcolumn()
            self.each_round_value.append(self.input)
            
        return self.input
    


class absorb:
    
    def __init__(self,input_hash):
        
        self.State= [[0,0,0,0,0],
                     [0,0,0,0,0],
                     [0,0,0,0,0],
                     [0,0,0,0,1],
                     [4,1,4,1,0]] 
        
        self.input_hash = input_hash
        self.input_len = len(input_hash)
        
        
    def xor_message(self):
        
        current_state = np.array(self.State[0])
        message = np.array(self.input_hash[0])
        self.State[0] = list(current_state^message)
        self.input_hash.pop(0)
        
    def result_absorb(self):
        
        for message in range(self.input_len):
            
            self.xor_message()
            print("Message {}".format(self.State[0]))
            permutation_ = permutation(self.State)
            self.State = permutation_.permutation_result()
            print("Permutation {} \n:".format(message))
            print(self.State)
            print("---------------------------------")
            
        return self.State
    


a = absorb(data)
_hash = a.result_absorb()

'''

def hash_func(a, k):
      a = a[:1] + k[:1]
      return a