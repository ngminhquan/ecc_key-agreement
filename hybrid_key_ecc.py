import field
from tinyec import registry
import random
import numpy as np
from hash_encrypt import Present, long_to_bytes, bytes_to_long, hash_function
import time

# take sample parameters
samplecurve = registry.get_curve("brainpoolP256r1")
p = samplecurve.field.p
print(p)
a = samplecurve.a
b = samplecurve.b
x_g = samplecurve.g.x
y_g = samplecurve.g.y
print(hex(x_g), y_g)
n = samplecurve.field.n
curve = field.Curve(a, b, p, n, x_g, y_g)


class key_agreement(object):
    def __init__(self, id_a: bytes, id_b: bytes, nonce_i: bytes, alpha_a: int, alpha_b: int, pu_b: int, k_m: int) -> None:
        self._id_a = id_a
        self._id_b = id_b
        self.nonce = nonce_i
        self._alpha_a:int = alpha_a
        self._alpha_b:int = alpha_b
        self._pu_b:int = pu_b
        self._k_m = k_m

        #encrypt & decrypt, use in cmac
    def present_encrypt(self, block: bytes) -> bytes:
        key = Present(self.ssk)
        return key.encrypt(block)

    def present_decrypt(self, block: bytes) -> bytes:
        key = Present(self.ssk)
        return key.decrypt(block)

    def verify_user_A(self):        #run at user B
        digest = hash_function(self._id_b + self._id_a + self.nonce)[:2]
        k_m_new = bytes_to_long(digest)
        if k_m_new != self._k_m:
            return 'INVALID user'
        else:
            return self._pu_b
            
    def gen_ssk(self):      #run at user A
        #ssk = chebyshev(alpha_a+alpha_b-k_m, x) mod p
        ssk = (self._alpha_a - self._k_m) * curve.g + self._pu_b
        ssk = ssk.x
        self.ssk = long_to_bytes(ssk)[:10]
        self.ssk_s = ssk

        #encrypt session key and send to B
        cp = self.present_encrypt(long_to_bytes(self._k_m, 8))
        self._cp = bytes_to_long(cp)
        self._cp_s = bytes_to_long(cp[:2])

        #find s = chebyshev(alpha_a - k_m - cp, x) mod p
        self._s = (self._alpha_a - self._k_m - self._cp_s) * curve.g
        #return self._s, self._cp
        return 0

    def recover_ssk(self):
        #find ssk' from s and cp
        ssk_new = (self._alpha_b + self._cp_s) * curve.g +  self._s
        ssk_new = long_to_bytes(ssk_new.x)[:10]

        #decrypt to receive k_m'
        _cp = long_to_bytes(self._cp, 8)
        k_m_test = self.present_decrypt(_cp)
        k_m_test = bytes_to_long(k_m_test)


        #verify
        return 0
        '''
        if k_m_test == self._k_m:
            print('VALID k_m')
            if ssk_new == self.ssk:
                print("VALID ssk")
                return ssk_new
            else:
                return 'INVALID ssk'
        else:
                return 'INVALID k_m'
        '''
    '''
    id_a = b'user_a'
    id_b = b'user_b'
    nonce_i = b'nonce'
    alpha_a = 567040
    alpha_b = 230882
    pu_b = 35903
    x = 842
    p = 46957
    k_m = hash_function(id_b + id_a + nonce_i)[:2]
    k_m = bytes_to_long(k_m)
    '''
# example key pairs
dA =b'81DB1EE100150FF2EA338D708271BE38300CB54241D79950F77B063039804F1D'

x_qA =b'44106E913F92BC02A1705D9953A8414DB95E1AAA49E81D9E85F929A8E3100BE5'
y_qA =b'8AB4846F11CACCB73CE49CBDD120F5A900A69FD32C272223F789EF10EB089BDC'

dB =b'55E40BC41E37E3E2AD25C3C6654511FFA8474A91A0032087593852D3E7D76BD3'

x_qB =b'8D2D688C6CF93E1160AD04CC4429117DC2C41825E1E9FCA0ADDD34E6F1B39F7B'
y_qB =b'990C57520812BE512641E47034832106BC7D3E8DD0E4C7F1136D7006547CEC6A'

x_Z =b'89AFC39D41D3B327814B80940B042590F96556EC91E6AE7939BCE31F3A18BF2B'
y_Z =b'49C27868F4ECA2179BFD7D59B1E3BF34C1DBDE61AE12931648F43E59632504DE'


id_a = b'user_a'
id_b = b'user_b'
nonce_i = b'nonce'
priKey1 = int(dA, 16)
priKey2 = int(dB, 16)
pubKey1 = (priKey1 * curve.g)
pubKey2 = (priKey2 * curve.g)
k_m = hash_function(id_b + id_a + nonce_i)[:2]
k_m = bytes_to_long(k_m)

hybrid_key = key_agreement(id_a, id_b, nonce_i, priKey1, priKey2, pubKey2, k_m)



count = 100
avg = 0
for i in range(count):
    start_time = time.time()

    # Đoạn code cần đo thời gian thực thi
    #a = hybrid_key.verify_user_A()
    b = hybrid_key.gen_ssk()
    c = hybrid_key.recover_ssk()

    #print(b)
    end_time = time.time()

    duration = end_time - start_time
    avg += duration

avg /= count
print("Thời gian chạy: {:.5f} giây".format(avg))