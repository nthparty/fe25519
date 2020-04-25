from parts import parts
from bitlist import bitlist
from fountains import fountains
from unittest import TestCase

from fe25519 import fe25519

def one_from_bytes(bs):
    ps = list(parts(bs, length=8))
    return fe25519([int.from_bytes(p, 'little') for p in ps])

def two_from_bytes(bs):
    ps = list(parts(bs, length=8))
    f1 = fe25519([int.from_bytes(p, 'little') for p in ps[:5]])
    f2 = fe25519([int.from_bytes(p, 'little') for p in ps[5:]])
    return (f1, f2)

def check_or_generate(self, fs, bits):
    if bits is not None:
        self.assertTrue(all(fs)) # Check that all tests succeeded.
    else:
        return bitlist(list(fs)).hex() # Return target bits for this test.

def check_or_generate_operation(self, fun, arity, bits):
    fs = fountains(8*5*arity, seed=0, limit=256, bits=bits, function=fun)
    return check_or_generate(self, fs, bits)

class TestFe25519(TestCase):
    def test_reduce(self, bits = 'b71ee55494c10540b2d3c4221793de6c6c722100387cab827ae1522affb5fd66'):
        fun = lambda bs: (one_from_bytes(bs).reduce()).to_bytes()
        return check_or_generate_operation(self, fun, 1, bits)

    def test_neg(self, bits = '7ee11aab6b3efabf4d2c3bdde86c2193938ddeffc783547d851eadd5004a0219'):
        fun = lambda bs: (-one_from_bytes(bs)).to_bytes()
        return check_or_generate_operation(self, fun, 1, bits)

    def test_abs(self, bits = 'fe4c4c172782fc006c73f6cc09ade2f4b82d57c562bea9887c2c525886a1ef17'):
        fun = lambda bs: (abs(one_from_bytes(bs))).to_bytes()
        return check_or_generate_operation(self, fun, 1, bits)

    def test_add(self, bits = '397e060905e137528ecc8421702c17535eda8d56683a018167d6f319f45a8234'):
        def fun(bs):
            (f1, f2) = two_from_bytes(bs)
            return (f1 + f2).to_bytes()
        return check_or_generate_operation(self, fun, 2, bits)

    def test_sub(self, bits = '70989bdb9b7f9ac91dcf56f3175efd39952d96f1a53c597f41dc0f59aa936d34'):
        def fun(bs):
            (f1, f2) = two_from_bytes(bs)
            return (f1 - f2).to_bytes()
        return check_or_generate_operation(self, fun, 2, bits)

    def test_mul(self, bits = '90a408821c55fd4e09213b390698021f2ae37265053d086be45c3bceffefe27b'):
        def fun(bs):
            (f1, f2) = two_from_bytes(bs)
            return (f1 * f2).to_bytes()
        return check_or_generate_operation(self, fun, 2, bits)

    def test_eq_true(self, bits = '0101010101010101010101010101010101010101010101010101010101010101'):
        def fun(bs):
            f0 = one_from_bytes(bs)
            return bytes([f0 == f0])
        return check_or_generate_operation(self, fun, 1, bits)

    def test_eq_false(self, bits = '0000000000000000000000000000000000000000000000000000000000000000'):
        def fun(bs):
            (f1, f2) = two_from_bytes(bs)
            return bytes([f1 == f2])
        return check_or_generate_operation(self, fun, 2, bits)

    def test_sq(self, bits = '8a7c83d71aacf24fcd76e5d24fa4d9fc7f6ee0e56333305ed8c4ae69565af95a'):
        fun = lambda bs: (one_from_bytes(bs).sq()).to_bytes()
        return check_or_generate_operation(self, fun, 1, bits)

    def test_sq2(self, bits = '69730f8c46dea00aa3377189a87c07277a6be1d3efec442b5c11a99fdd67f230'):
        fun = lambda bs: (one_from_bytes(bs).sq2()).to_bytes()
        return check_or_generate_operation(self, fun, 1, bits)
  
    def test_pow22523(self, bits = '4601cde640c8e05a4e63df3edc2a9d472851072b6b361eaaebcf781c0a116150'):
        fun = lambda bs: (one_from_bytes(bs).pow22523()).to_bytes()
        return check_or_generate_operation(self, fun, 1, bits)
  
    def test_invert(self, bits = 'f103890f12e1533aee66007a2a7b051a8e9f378fded8291bb0110a95ac55d059'):
        fun = lambda bs: (one_from_bytes(bs).invert()).to_bytes()
        return check_or_generate_operation(self, fun, 1, bits)
  
    def test_chi25519(self, bits = '64a9f0ae1ce3dda09b86ff4d1ca0fcf31bad8f65f3ce025b6debdb20abefc85a'):
        fun = lambda bs: (one_from_bytes(bs).chi25519()).to_bytes()
        return check_or_generate_operation(self, fun, 1, bits)

if __name__ == "__main__":
    # Generate reference bit lists for tests.
    test_fe25519 = TestFe25519()
    for m in [m for m in dir(test_fe25519) if m.startswith('test_')]:
        print(m + ': ' + getattr(test_fe25519, m)(bits=None))
