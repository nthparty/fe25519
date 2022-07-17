"""
Test suite containing functional unit tests for the exported primitives and
classes.
"""
from __future__ import annotations
from typing import Tuple, Union, Optional, Callable, Iterable
from unittest import TestCase
from parts import parts
from bitlist import bitlist
from fountains import fountains

from fe25519.fe25519 import fe25519

def one_from_bytes(bs: bytes) -> fe25519:
    """
    Generate one element from a given bit sequence obtained
    using :obj:`fountains`.
    """
    ps = list(parts(bs, length=8))
    return fe25519([int.from_bytes(p, 'little') for p in ps])

def two_from_bytes(bs: bytes) -> Tuple[fe25519, fe25519]:
    """
    Generate two elements from a given bit sequence obtained
    using :obj:`fountains`.
    """
    ps = list(parts(bs, length=8))
    f1 = fe25519([int.from_bytes(p, 'little') for p in ps[:5]])
    f2 = fe25519([int.from_bytes(p, 'little') for p in ps[5:]])
    return (f1, f2)

def check_or_generate(
        testcase: TestCase,
        fs: Union[Iterable[int], Iterable[bool]],
        bits: Optional[str]
    ) -> Optional[str]:
    """
    Wrapper that enables switching between performing a test or
    generating specifications compatible with :obj:`fountains`.
    """
    if bits is None:
        return bitlist(list(fs)).hex() # Return target bits for this test.

    testcase.assertTrue(all(fs)) # Check that all tests succeeded.
    return None # Do not return a test input.

def check_or_generate_operation(
        testcase: TestCase,
        fun: Union[Callable[[bytes], bytes], Callable[[bytes], bitlist]],
        arity: int,
        bits: Optional[str]
    ) -> Optional[str]:
    """
    Wrapper that enables switching between performing a test or
    generating specifications compatible with :obj:`fountains`.
    """
    fs = fountains(
        8 * 5 * arity,
        seed=bytes(0), # This is also the default; explicit for clarity.
        limit=256,
        bits=bits,
        function=fun
    )
    return check_or_generate(testcase, fs, bits)

class Test_fe25519(TestCase):
    """
    Tests for all class methods.
    """
    # pylint: disable=too-many-public-methods,missing-function-docstring
    def test_one(
            self,
            bits='b71ee55494c10540b2d3c4221793de6c6c722100387cab827ae1522affb5fd66'
        ):
        fun = lambda bs: (one_from_bytes(bs) * fe25519.one()).to_bytes()
        return check_or_generate_operation(self, fun, 1, bits)

    def test_reduce(
            self,
            bits='b71ee55494c10540b2d3c4221793de6c6c722100387cab827ae1522affb5fd66'
        ):
        fun = lambda bs: (one_from_bytes(bs).reduce()).to_bytes()
        return check_or_generate_operation(self, fun, 1, bits)

    def test_add(
            self,
            bits='397e060905e137528ecc8421702c17535eda8d56683a018167d6f319f45a8234'
        ):
        def fun(bs):
            (f1, f2) = two_from_bytes(bs)
            return (f1 + f2).to_bytes()
        return check_or_generate_operation(self, fun, 2, bits)

    def test_neg(
            self,
            bits='7ee11aab6b3efabf4d2c3bdde86c2193938ddeffc783547d851eadd5004a0219'
        ):
        fun = lambda bs: (-one_from_bytes(bs)).to_bytes()
        return check_or_generate_operation(self, fun, 1, bits)

    def test_abs(
            self,
            bits='fe4c4c172782fc006c73f6cc09ade2f4b82d57c562bea9887c2c525886a1ef17'
        ):
        fun = lambda bs: (abs(one_from_bytes(bs))).to_bytes()
        return check_or_generate_operation(self, fun, 1, bits)

    def test_sub(
            self,
            bits='70989bdb9b7f9ac91dcf56f3175efd39952d96f1a53c597f41dc0f59aa936d34'
        ):
        def fun(bs):
            (f1, f2) = two_from_bytes(bs)
            return (f1 - f2).to_bytes()
        return check_or_generate_operation(self, fun, 2, bits)

    def test_mul(
            self,
            bits='90a408821c55fd4e09213b390698021f2ae37265053d086be45c3bceffefe27b'
        ):
        def fun(bs):
            (f1, f2) = two_from_bytes(bs)
            return (f1 * f2).to_bytes()
        return check_or_generate_operation(self, fun, 2, bits)

    def test_sq(
            self,
            bits='8a7c83d71aacf24fcd76e5d24fa4d9fc7f6ee0e56333305ed8c4ae69565af95a'
        ):
        fun = lambda bs: (one_from_bytes(bs)**2).to_bytes()
        return check_or_generate_operation(self, fun, 1, bits)

    def test_sq2(
            self,
            bits='69730f8c46dea00aa3377189a87c07277a6be1d3efec442b5c11a99fdd67f230'
        ):
        fun = lambda bs: (one_from_bytes(bs).sq2()).to_bytes()
        return check_or_generate_operation(self, fun, 1, bits)

    def test_pow22523(
            self,
            bits='4601cde640c8e05a4e63df3edc2a9d472851072b6b361eaaebcf781c0a116150'
        ):
        fun = lambda bs: (one_from_bytes(bs).pow22523()).to_bytes()
        return check_or_generate_operation(self, fun, 1, bits)

    def test_invert(
            self,
            bits='f103890f12e1533aee66007a2a7b051a8e9f378fded8291bb0110a95ac55d059'
        ):
        fun = lambda bs: (one_from_bytes(bs)**(-1)).to_bytes()
        return check_or_generate_operation(self, fun, 1, bits)

    def test_invert_op(
            self,
            bits='f103890f12e1533aee66007a2a7b051a8e9f378fded8291bb0110a95ac55d059'
        ):
        fun = lambda bs: (~one_from_bytes(bs)).to_bytes()
        return check_or_generate_operation(self, fun, 1, bits)

    def test_sqrt_ratio_m1_ristretto255(
            self,
            bits='e08f25034216acaf3d92d080192fa7ec1585693caa6931a84b4261100c071d08'
        ):
        def fun(bs):
            (f1, f2) = two_from_bytes(bs)
            return f1.sqrt_ratio_m1_ristretto255(f2)[0].to_bytes()
        return check_or_generate_operation(self, fun, 2, bits)

    def test_chi25519(
            self,
            bits='64a9f0ae1ce3dda09b86ff4d1ca0fcf31bad8f65f3ce025b6debdb20abefc85a'
        ):
        fun = lambda bs: (one_from_bytes(bs).chi25519()).to_bytes()
        return check_or_generate_operation(self, fun, 1, bits)

    def test_eq_true(
            self,
            bits='0101010101010101010101010101010101010101010101010101010101010101'
        ):
        def fun(bs):
            f0 = one_from_bytes(bs)
            return bytes([f0 == f0]) # pylint: disable=comparison-with-itself
        return check_or_generate_operation(self, fun, 1, bits)

    def test_eq_false(
            self,
            bits='0000000000000000000000000000000000000000000000000000000000000000'
        ):
        def fun(bs):
            (f1, f2) = two_from_bytes(bs)
            return bytes([f1 == f2])
        return check_or_generate_operation(self, fun, 2, bits)

    def test_is_zero(
            self,
            bits='0000000000000000000000000000000000000000000000000000000000000000'
        ):
        fun = lambda bs: bitlist([one_from_bytes(bs).is_zero()])
        return check_or_generate_operation(self, fun, 1, bits)

    def test_is_negative(
            self,
            bits='5d52a943b343f940dea032ee1e3e3c98d45f76c55ac2020a06cd007279141271'
        ):
        fun = lambda bs: bitlist([one_from_bytes(bs).is_negative()])
        return check_or_generate_operation(self, fun, 1, bits)

    def test_cmov(
            self,
            bits='01da9d156e3e03043adaad53bcf8af55150ef319da198f44d6c8df44ca5fb324'
        ):
        def fun(bs):
            ((f1, f2), b) = (two_from_bytes(bs), bs[0] % 2)
            return f1.cmov(f2, b).to_bytes()
        return check_or_generate_operation(self, fun, 2, bits)

    def test_pow(
            self,
            bits='0000000000000000000000000000000000000000000000000000000000000000'
        ):
        fun = lambda bs: bitlist([0 if one_from_bytes(bs)**(0) is None else 255]).to_bytes()
        return check_or_generate_operation(self, fun, 1, bits)

    def test_str(
            self,
            bits='0000000000000000000000000000000000000000000000000000000000000000'
        ):
        def fun(bs):
            f = one_from_bytes(bs)
            return bitlist([
                0 if eval(str(f)) == f else 255 # pylint: disable=eval-used
            ]).to_bytes()
        return check_or_generate_operation(self, fun, 1, bits)

    def test_bytes(
            self,
            bits='0000000000000000000000000000000000000000000000000000000000000000'
        ):
        def fun(bs):
            f = one_from_bytes(bs)
            return bitlist([0 if fe25519.from_bytes(f.to_bytes()) == f else 255]).to_bytes()
        return check_or_generate_operation(self, fun, 1, bits)

    def test_bytes_op(
            self,
            bits='0000000000000000000000000000000000000000000000000000000000000000'
        ):
        def fun(bs):
            f = one_from_bytes(bs)
            return bitlist([0 if fe25519.from_bytes(bytes(f)) == f else 255]).to_bytes()
        return check_or_generate_operation(self, fun, 1, bits)

if __name__ == '__main__':
    # Generate specifications for tests.
    test_fe25519 = Test_fe25519()
    for m in [m for m in dir(test_fe25519) if m.startswith('test_')]:
        print(m + ': ' + getattr(test_fe25519, m)(bits=None))
