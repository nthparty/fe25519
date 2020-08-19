"""Field element data structure and operations.

Native Python implementation of Ed25519 field elements and
operations.
"""

from __future__ import annotations
from typing import Tuple, Sequence
import doctest

TWO_TO_64 = 2**64
TWO_TO_128 = 2**128

class fe25519():
    """
    Class for field elements.
    """

    # Precomputed static constants.
    d = None
    d2 = None
    sqrtm1 = None
    invsqrtamd = None
    onemsqd = None
    sqdmone = None
    sqrtadm1 = None
    curve25519_A = None

    @staticmethod
    def zero() -> fe25519:
        """Constant corresponding to the zero element."""
        return fe25519([0, 0, 0, 0, 0])

    @staticmethod
    def one() -> fe25519:
        """Constant corresponding to the multiplicative identity element."""
        return fe25519([1, 0, 0, 0, 0])

    def __init__(self: fe25519, ns: Sequence[int]):
        """Create a field element using a list of five 64-bit integers."""
        self.ns = ns

    def copy(self: fe25519):
        """Create a copy of an element instance."""
        return fe25519(list(self.ns))

    def reduce(self: fe25519) -> fe25519:
        """Element reduction."""
        t = self.ns # 128-bit integers.
        mask = 2251799813685247

        t[1] = (t[1] + (t[0] >> 51)) % TWO_TO_128
        t[0] &= mask
        t[2] = (t[2] + (t[1] >> 51)) % TWO_TO_128
        t[1] &= mask
        t[3] = (t[3] + (t[2] >> 51)) % TWO_TO_128
        t[2] &= mask
        t[4] = (t[4] + (t[3] >> 51)) % TWO_TO_128
        t[3] &= mask
        t[0] = (t[0] + 19 * (t[4] >> 51)) % TWO_TO_128
        t[4] &= mask

        t[1] = (t[1] + (t[0] >> 51)) % TWO_TO_128
        t[0] &= mask
        t[2] = (t[2] + (t[1] >> 51)) % TWO_TO_128
        t[1] &= mask
        t[3] = (t[3] + (t[2] >> 51)) % TWO_TO_128
        t[2] &= mask
        t[4] = (t[4] + (t[3] >> 51)) % TWO_TO_128
        t[3] &= mask
        t[0] = (t[0] + 19 * (t[4] >> 51)) % TWO_TO_128
        t[4] &= mask

        # Now t is between 0 and 2^255-1, properly carried.
        # Сase 1: between 0 and 2^255-20. Case 2: between 2^255-19 and 2^255-1.

        t[0] = (t[0] + 19) % TWO_TO_128

        t[1] = (t[1] + (t[0] >> 51)) % TWO_TO_128
        t[0] &= mask
        t[2] = (t[2] + (t[1] >> 51)) % TWO_TO_128
        t[1] &= mask
        t[3] = (t[3] + (t[2] >> 51)) % TWO_TO_128
        t[2] &= mask
        t[4] = (t[4] + (t[3] >> 51)) % TWO_TO_128
        t[3] &= mask
        t[0] = (t[0] + 19 * (t[4] >> 51)) % TWO_TO_128
        t[4] &= mask

        # Now between 19 and 2^255-1 in both cases, and offset by 19.

        t[0] = (t[0] + 2251799813685248 - 19) % TWO_TO_128
        t[1] = (t[1] + 2251799813685248 - 1) % TWO_TO_128
        t[2] = (t[2] + 2251799813685248 - 1) % TWO_TO_128
        t[3] = (t[3] + 2251799813685248 - 1) % TWO_TO_128
        t[4] = (t[4] + 2251799813685248 - 1) % TWO_TO_128

        # Now between 2^255 and 2^256-20, and offset by 2^255.

        t[1] = (t[1] + (t[0] >> 51)) % TWO_TO_128
        t[0] &= mask
        t[2] = (t[2] + (t[1] >> 51)) % TWO_TO_128
        t[1] &= mask
        t[3] = (t[3] + (t[2] >> 51)) % TWO_TO_128
        t[2] &= mask
        t[4] = (t[4] + (t[3] >> 51)) % TWO_TO_128
        t[3] &= mask
        t[4] &= mask

        return fe25519(t)

    def __add__(self: fe25519, other: fe25519) -> fe25519:
        """Addition of elements."""
        return fe25519([(m+n)%TWO_TO_64 for (m, n) in zip(self.ns, other.ns)])

    def __neg__(self: fe25519) -> fe25519:
        """Negation of an element."""
        return fe25519.zero() - self

    def cneg(self: fe25519, b: int) -> fe25519:
        """Conditional negation of an element."""
        return self.copy().cmov(-self, b)

    def __abs__(self: fe25519) -> fe25519:
        """Absolute value of an element."""
        return self.cneg(self.is_negative())

    def __sub__(self: fe25519, other: fe25519) -> fe25519:
        """Subtraction of elements."""
        mask = 2251799813685247

        (h0, h1, h2, h3, h4) = other.ns

        h1 = (h1 + (h0 >> 51)) % TWO_TO_64
        h0 &= mask
        h2 = (h2 + (h1 >> 51)) % TWO_TO_64
        h1 &= mask
        h3 = (h3 + (h2 >> 51)) % TWO_TO_64
        h2 &= mask
        h4 = (h4 + (h3 >> 51)) % TWO_TO_64
        h3 &= mask
        h0 = (h0 + 19 * (h4 >> 51)) % TWO_TO_64
        h4 &= mask

        return fe25519([
            ((self.ns[0] + 4503599627370458) - h0) % TWO_TO_64,
            ((self.ns[1] + 4503599627370494) - h1) % TWO_TO_64,
            ((self.ns[2] + 4503599627370494) - h2) % TWO_TO_64,
            ((self.ns[3] + 4503599627370494) - h3) % TWO_TO_64,
            ((self.ns[4] + 4503599627370494) - h4) % TWO_TO_64
        ])

    def __mul__(self: fe25519, other: fe25519) -> fe25519:
        """Multiplication of elements."""
        mask = 2251799813685247 # 64-bit integer.
        (f, g) = (self.ns, other.ns) # 64-bit integers.
        r = [None, None, None, None, None] # 128-bit integers.
        carry = None # 128-bit integer.
        r0 = [None, None, None, None, None] # 64-bit integers.

        f1_19 = (19 * f[1]) % TWO_TO_64
        f2_19 = (19 * f[2]) % TWO_TO_64
        f3_19 = (19 * f[3]) % TWO_TO_64
        f4_19 = (19 * f[4]) % TWO_TO_64

        r[0] = (f[0]*g[0] + f1_19*g[4] + f2_19*g[3] + f3_19*g[2] + f4_19*g[1]) % TWO_TO_128
        r[1] = (f[0]*g[1] + f[1]*g[0] + f2_19*g[4] + f3_19*g[3] + f4_19*g[2]) % TWO_TO_128
        r[2] = (f[0]*g[2] + f[1]*g[1] + f[2]*g[0] + f3_19*g[4] + f4_19*g[3]) % TWO_TO_128
        r[3] = (f[0]*g[3] + f[1]*g[2] + f[2]*g[1] + f[3]*g[0] + f4_19*g[4]) % TWO_TO_128
        r[4] = (f[0]*g[4] + f[1]*g[3] + f[2]*g[2] + f[3]*g[1] + f[4]*g[0]) % TWO_TO_128

        r0[0] = (r[0] % TWO_TO_64) & mask
        r[1] = (r[1] + (r[0] >> 51)) % TWO_TO_128
        r0[1] = (r[1] % TWO_TO_64) & mask
        r[2] = (r[2] + (r[1] >> 51)) % TWO_TO_128
        r0[2] = (r[2] % TWO_TO_64) & mask
        r[3] = (r[3] + (r[2] >> 51)) % TWO_TO_128
        r0[3] = (r[3] % TWO_TO_64) & mask
        r[4] = (r[4] + (r[3] >> 51)) % TWO_TO_128
        r0[4] = (r[4] % TWO_TO_64) & mask
        r0[0] = (r0[0] + (19*((r[4] >> 51) % TWO_TO_64))) % TWO_TO_64
        carry = r0[0] >> 51
        r0[0] &= mask
        r0[1] = (r0[1] + (carry % TWO_TO_64)) % TWO_TO_64
        carry = r0[1] >> 51
        r0[1] &= mask
        r0[2] = (r0[2] + (carry % TWO_TO_64)) % TWO_TO_64

        return fe25519(r0)

    def sq(self: fe25519) -> fe25519:
        """Squaring of an element."""
        mask = 2251799813685247 # 64-bit integer.
        f = self.ns # 64-bit integers.
        r = [None, None, None, None, None] # 128-bit integers.
        carry = None # 128-bit integer.
        r0 = [None, None, None, None, None] # 64-bit integers.

        f0_2 = (f[0] << 1) % TWO_TO_64
        f1_2 = (f[1] << 1) % TWO_TO_64

        f1_38 = (38 * f[1]) % TWO_TO_64
        f2_38 = (38 * f[2]) % TWO_TO_64
        f3_38 = (38 * f[3]) % TWO_TO_64

        f3_19 = (19 * f[3]) % TWO_TO_64
        f4_19 = (19 * f[4]) % TWO_TO_64

        r[0] = (f[0]*f[0] + f1_38*f[4] + f2_38*f[3]) % TWO_TO_128
        r[1] = (f0_2*f[1] + f2_38*f[4] + f3_19*f[3]) % TWO_TO_128
        r[2] = (f0_2*f[2] + f[1]*f[1] + f3_38*f[4]) % TWO_TO_128
        r[3] = (f0_2*f[3] + f1_2*f[2] + f4_19*f[4]) % TWO_TO_128
        r[4] = (f0_2*f[4] + f1_2*f[3] + f[2]*f[2]) % TWO_TO_128

        r0[0] = (r[0] % TWO_TO_64) & mask
        r[1] = (r[1] + (r[0] >> 51)) % TWO_TO_128
        r0[1] = (r[1] % TWO_TO_64) & mask
        r[2] = (r[2] + (r[1] >> 51)) % TWO_TO_128
        r0[2] = (r[2] % TWO_TO_64) & mask
        r[3] = (r[3] + (r[2] >> 51)) % TWO_TO_128
        r0[3] = (r[3] % TWO_TO_64) & mask
        r[4] = (r[4] + (r[3] >> 51)) % TWO_TO_128
        r0[4] = (r[4] % TWO_TO_64) & mask
        r0[0] = (r0[0] + (19*((r[4] >> 51) % TWO_TO_64))) % TWO_TO_64
        carry = r0[0] >> 51
        r0[0] &= mask
        r0[1] = (r0[1] + (carry % TWO_TO_64)) % TWO_TO_64
        carry = r0[1] >> 51
        r0[1] &= mask
        r0[2] = (r0[2] + (carry % TWO_TO_64)) % TWO_TO_64

        return fe25519(r0)

    def sq2(self: fe25519) -> fe25519:
        """Repeated squaring of an element."""
        mask = 2251799813685247
        f = self.ns # 64-bit integers.
        r = [None, None, None, None, None] # 128-bit integers.
        carry = None # 128-bit integer.
        r0 = [None, None, None, None, None] # 64-bit integers.

        f0_2 = (f[0] << 1) % TWO_TO_64
        f1_2 = (f[1] << 1) % TWO_TO_64

        f1_38 = (38 * f[1]) % TWO_TO_64
        f2_38 = (38 * f[2]) % TWO_TO_64
        f3_38 = (38 * f[3]) % TWO_TO_64

        f3_19 = (19 * f[3]) % TWO_TO_64
        f4_19 = (19 * f[4]) % TWO_TO_64

        r[0] = (f[0]*f[0] + f1_38*f[4] + f2_38*f[3]) % TWO_TO_128
        r[1] = (f0_2*f[1] + f2_38*f[4] + f3_19*f[3]) % TWO_TO_128
        r[2] = (f0_2*f[2] + f[1]*f[1] + f3_38*f[4]) % TWO_TO_128
        r[3] = (f0_2*f[3] + f1_2*f[2] + f4_19*f[4]) % TWO_TO_128
        r[4] = (f0_2*f[4] + f1_2*f[3] + f[2]*f[2]) % TWO_TO_128

        r[0] <<= 1
        r[1] <<= 1
        r[2] <<= 1
        r[3] <<= 1
        r[4] <<= 1

        r0[0] = (r[0] % TWO_TO_64) & mask
        carry = r[0] >> 51
        r[1] = (r[1] + carry) % TWO_TO_128
        r0[1] = (r[1] % TWO_TO_64) & mask
        carry = r[1] >> 51
        r[2] = (r[2] + carry) % TWO_TO_128

        r0[2] = (r[2] % TWO_TO_64) & mask
        carry = r[2] >> 51
        r[3] = (r[3] + carry) % TWO_TO_128
        r0[3] = (r[3] % TWO_TO_64) & mask
        carry = r[3] >> 51
        r[4] = (r[4] + carry) % TWO_TO_128
        r0[4] = (r[4] % TWO_TO_64) & mask
        carry = r[4] >> 51
        r0[0] = (r0[0] + 19*carry) % TWO_TO_64
        carry = r0[0] >> 51
        r0[0] &= mask
        r0[1] = (r0[1] + (carry % TWO_TO_64)) % TWO_TO_64
        carry = r0[1] >> 51
        r0[1] &= mask
        r0[2] = (r0[2] + (carry % TWO_TO_64)) % TWO_TO_64

        return fe25519(r0)

    def __pow__(self: fe25519, e: int) -> fe25519:
        """Synonym for squaring and inversion."""
        if e == 2: # Squaring.
            return self.sq()
        if e == -1: # Inversion.
            return self.invert()

        # Supplied exponent is not supported.
        return None

    def pow22523(self: fe25519) -> fe25519:
        """Exponentiation (special fixed exponent)."""
        z = self.copy()
        t0 = z.sq()
        t1 = t0.sq()
        t1 = t1.sq()
        t1 = z * t1
        t0 = t0 * t1
        t0 = t0.sq()
        t0 = t1 * t0
        t1 = t0.sq()
        for _ in range(1, 5):
            t1 = t1.sq()
        t0 = t1 * t0
        t1 = t0.sq()
        for _ in range(1, 10):
            t1 = t1.sq()
        t1 = t1 * t0
        t2 = t1.sq()
        for _ in range(1, 20):
            t2 = t2.sq()
        t1 = t2 * t1
        t1 = t1.sq()
        for _ in range(1, 10):
            t1 = t1.sq()
        t0 = t1 * t0
        t1 = t0.sq()
        for _ in range(1, 50):
            t1 = t1.sq()
        t1 = t1 * t0
        t2 = t1.sq()
        for _ in range(1, 100):
            t2 = t2.sq()
        t1 = t2 * t1
        t1 = t1.sq()
        for _ in range(1, 50):
            t1 = t1.sq()
        t0 = t1 * t0
        t0 = t0.sq()
        t0 = t0.sq()
        return t0 * z

    def invert(self: fe25519) -> fe25519:
        """Inversion of an element."""
        z = self.copy()
        t0 = z.sq()
        t1 = t0.sq()
        t1 = t1.sq()
        t1 = z * t1
        t0 = t0 * t1
        t2 = t0.sq()
        t1 = t1 * t2
        t2 = t1.sq()
        for _ in range(1, 5):
            t2 = t2.sq()
        t1 = t2 * t1
        t2 = t1.sq()
        for _ in range(1, 10):
            t2 = t2.sq()
        t2 = t2 * t1
        t3 = t2.sq()
        for _ in range(1, 20):
            t3 = t3.sq()
        t2 = t3 * t2
        t2 = t2.sq()
        for _ in range(1, 10):
            t2 = t2.sq()
        t1 = t2 * t1
        t2 = t1.sq()
        for _ in range(1, 50):
            t2 = t2.sq()
        t2 = t2 * t1
        t3 = t2.sq()
        for _ in range(1, 100):
            t3 = t3.sq()
        t2 = t3 * t2
        t2 = t2.sq()
        for _ in range(1, 50):
            t2 = t2.sq()
        t1 = t2 * t1
        t1 = t1.sq()
        for _ in range(1, 5):
            t1 = t1.sq()
        return t1 * t0

    def sqrt_ratio_m1_ristretto255(self: fe25519, v: fe25519) -> Tuple[fe25519, int]:
        """Specialized root operation."""
        u = self

        v3 = v.sq()
        v3 = v3 * v                         # v3 = v^3
        x = v3.sq()
        x = x * v
        x = x * u                           # x = uv^7

        x = x.pow22523()                    # x = (uv^7)^((q-5)/8)
        x = x * v3
        x = x * u                           # x = uv^3(uv^7)^((q-5)/8)

        vxx = x.sq()
        vxx = vxx * v                       # vx^2
        m_root_check = vxx - u              # vx^2-u
        p_root_check = vxx + u              # vx^2+u
        f_root_check = u * fe25519.sqrtm1   # u*sqrt(-1)
        f_root_check = vxx + f_root_check   # vx^2+u*sqrt(-1)
        has_m_root = m_root_check.is_zero()
        has_p_root = p_root_check.is_zero()
        has_f_root = f_root_check.is_zero()
        x_sqrtm1 = x * fe25519.sqrtm1       # x*sqrt(-1)

        x = x.cmov(x_sqrtm1, has_p_root | has_f_root)
        x = abs(x)

        return (x, has_m_root | has_p_root)

    def chi25519(self: fe25519) -> fe25519:
        """Specialized root function (for elligator)."""
        t0 = self.sq()
        t1 = t0 * self
        t0 = t1.sq()
        t2 = t0.sq()
        t2 = t2.sq()
        t2 = t2 * t0
        t1 = t2 * self
        t2 = t1.sq()

        for _ in range(1, 5):
            t2 = t2.sq()
        t1 = t2 * t1
        t2 = t1.sq()
        for _ in range(1, 10):
            t2 = t2.sq()
        t2 = t2 * t1
        t3 = t2.sq()
        for _ in range(1, 20):
            t3 = t3.sq()
        t2 = t3 * t2
        t2 = t2.sq()
        for _ in range(1, 10):
            t2 = t2.sq()
        t1 = t2 * t1
        t2 = t1.sq()
        for _ in range(1, 50):
            t2 = t2.sq()
        t2 = t2 * t1
        t3 = t2.sq()
        for _ in range(1, 100):
            t3 = t3.sq()
        t2 = t3 * t2
        t2 = t2.sq()
        for _ in range(1, 50):
            t2 = t2.sq()
        t1 = t2 * t1
        t1 = t1.sq()
        for _ in range(1, 4):
            t1 = t1.sq()

        return t1 * t0

    def __eq__(self: fe25519, other: fe25519) -> bool:
        """Equality of elements."""
        return self.ns == other.ns

    def is_zero(self: fe25519) -> int:
        """Determine whether an element is zero."""
        bs = self.to_bytes()
        d = 0
        for b in bs:
            d |= b
        return 1 & ((d - 1) >> 8)

    def is_negative(self: fe25519) -> int:
        """Determine whether an element is negative."""
        bs = self.to_bytes()
        return bs[0] & 1

    def cmov(self: fe25519, g: fe25519, b: int) -> fe25519:
        """Conditional selection of an element based on boolean integer."""
        mask = TWO_TO_64 - b
        pairs = zip(self.ns, g.ns)
        return fe25519([fi ^ ((fi ^ gi) & mask) for (fi, gi) in pairs])

    @staticmethod
    def from_bytes(bs: bytes) -> fe25519:
        """Assembly of an element instance from its byte representation."""
        mask = 2251799813685247

        def load64_le(bs):
            w = bs[0]
            w |= bs[1] <<  8
            w |= bs[2] << 16
            w |= bs[3] << 24
            w |= bs[4] << 32
            w |= bs[5] << 40
            w |= bs[6] << 48
            w |= bs[7] << 56
            return w

        return fe25519([
            (load64_le(bs[0:8])) & mask,
            (load64_le(bs[6:14]) >> 3) & mask,
            (load64_le(bs[12:20]) >> 6) & mask,
            (load64_le(bs[19:27]) >> 1) & mask,
            (load64_le(bs[24:32]) >> 12) & mask
        ])

    def to_bytes(self: fe25519) -> bytes:
        """Byte representation of an element."""
        t = self.reduce().ns

        t0 = t[0] | ((t[1] << 51) % TWO_TO_64)
        t1 = (t[1] >> 13) | ((t[2] << 38) % TWO_TO_64)
        t2 = (t[2] >> 26) | ((t[3] << 25) % TWO_TO_64)
        t3 = (t[3] >> 39) | ((t[4] << 12) % TWO_TO_64)

        bs = bytearray()
        bs.extend(t0.to_bytes(8, 'little'))
        bs.extend(t1.to_bytes(8, 'little'))
        bs.extend(t2.to_bytes(8, 'little'))
        bs.extend(t3.to_bytes(8, 'little'))
        return bs

    def __str__(self: fe25519) -> str:
        """String representation of an element."""
        return 'fe25519(' + str(self.ns) + ')'

    def __repr__(self: fe25519) -> str:
        """String representation of an element."""
        return str(self) # pragma: no cover

# Precomputed static constants.
fe25519.d = fe25519([
    929955233495203, 466365720129213, 1662059464998953, 2033849074728123, 1442794654840575
])
fe25519.d2 = fe25519([
    1859910466990425, 932731440258426, 1072319116312658, 1815898335770999, 633789495995903
])
fe25519.sqrtm1 = fe25519([
    1718705420411056, 234908883556509, 2233514472574048, 2117202627021982, 765476049583133
])
fe25519.invsqrtamd = fe25519([
    278908739862762, 821645201101625, 8113234426968, 1777959178193151, 2118520810568447
])
fe25519.onemsqd = fe25519([
    1136626929484150, 1998550399581263, 496427632559748, 118527312129759, 45110755273534
])
fe25519.sqdmone = fe25519([
    1507062230895904, 1572317787530805, 683053064812840, 317374165784489, 1572899562415810
])
fe25519.sqrtadm1 = fe25519([
    2241493124984347, 425987919032274, 2207028919301688, 1220490630685848, 974799131293748
])
fe25519.curve25519_A = fe25519([486662, 0, 0, 0, 0])

if __name__ == "__main__":
    doctest.testmod() # pragma: no cover
