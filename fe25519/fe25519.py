"""Field element data structure and operations.

Native Python implementation of Ed25519 field elements and
operations.
"""

from __future__ import annotations
from typing import Sequence
import doctest

class Fe25519Error(Exception):
    """A general-purpose catch-all for any usage error."""

    def __init__(self, message):
        super(Fe25519Error, self).__init__(message)
        self.message = message

    def __str__(self):
        return repr(self.message)

class fe25519():
    """
    Class for field elements.
    """

    def __init__(self: fe25519, ns: Sequence[int]):
        """Create a field element using a list of five 64-bit integers."""
        self.ns = ns

    def copy(self: fe25519):
        return fe25519([n for n in self.ns])

    @staticmethod
    def zero() -> fe25519:
        return fe25519([0,0,0,0,0])

    @staticmethod
    def one() -> fe25519:
        return fe25519([1,0,0,0,0])

    def reduce(self: fe25519) -> fe25519:
        t = self.ns # 128-bit integers.
        mask = 2251799813685247

        t[1] = (t[1] + (t[0] >> 51)) % (2**128)
        t[0] &= mask
        t[2] = (t[2] + (t[1] >> 51)) % (2**128)
        t[1] &= mask
        t[3] = (t[3] + (t[2] >> 51)) % (2**128)
        t[2] &= mask
        t[4] = (t[4] + (t[3] >> 51)) % (2**128)
        t[3] &= mask
        t[0] = (t[0] + 19 * (t[4] >> 51)) % (2**128)
        t[4] &= mask

        t[1] = (t[1] + (t[0] >> 51)) % (2**128)
        t[0] &= mask
        t[2] = (t[2] + (t[1] >> 51)) % (2**128)
        t[1] &= mask
        t[3] = (t[3] + (t[2] >> 51)) % (2**128)
        t[2] &= mask
        t[4] = (t[4] + (t[3] >> 51)) % (2**128)
        t[3] &= mask
        t[0] = (t[0] + 19 * (t[4] >> 51)) % (2**128)
        t[4] &= mask

        # Now t is between 0 and 2^255-1, properly carried.
        # Сase 1: between 0 and 2^255-20. Case 2: between 2^255-19 and 2^255-1.

        t[0] = (t[0] + 19) % (2**128)

        t[1] = (t[1] + (t[0] >> 51)) % (2**128)
        t[0] &= mask
        t[2] = (t[2] + (t[1] >> 51)) % (2**128)
        t[1] &= mask
        t[3] = (t[3] + (t[2] >> 51)) % (2**128)
        t[2] &= mask
        t[4] = (t[4] + (t[3] >> 51)) % (2**128)
        t[3] &= mask
        t[0] = (t[0] + 19 * (t[4] >> 51)) % (2**128)
        t[4] &= mask

        # Now between 19 and 2^255-1 in both cases, and offset by 19.

        t[0] = (t[0] + 2251799813685248 - 19) % (2**128)
        t[1] = (t[1] + 2251799813685248 - 1) % (2**128)
        t[2] = (t[2] + 2251799813685248 - 1) % (2**128)
        t[3] = (t[3] + 2251799813685248 - 1) % (2**128)
        t[4] = (t[4] + 2251799813685248 - 1) % (2**128)

        # Now between 2^255 and 2^256-20, and offset by 2^255.

        t[1] = (t[1] + (t[0] >> 51)) % (2**128)
        t[0] &= mask
        t[2] = (t[2] + (t[1] >> 51)) % (2**128)
        t[1] &= mask
        t[3] = (t[3] + (t[2] >> 51)) % (2**128)
        t[2] &= mask;
        t[4] = (t[4] + (t[3] >> 51)) % (2**128)
        t[3] &= mask
        t[4] &= mask

        return fe25519(t)

    def __add__(self: fe25519, other: fe25519) -> fe25519:
        return fe25519([(m+n)%(2**64) for (m,n) in zip(self.ns, other.ns)])

    def __neg__(self: fe25519) -> fe25519:
        return fe25519.zero() - self

    def __sub__(self: fe25519, other: fe25519) -> fe25519:
        mask = 2251799813685247

        (h0, h1, h2, h3, h4) = other.ns

        h1 = (h1 + (h0 >> 51)) % (2**64)
        h0 &= mask
        h2 = (h2 + (h1 >> 51)) % (2**64)
        h1 &= mask
        h3 = (h3 + (h2 >> 51)) % (2**64)
        h2 &= mask
        h4 = (h4 + (h3 >> 51)) % (2**64)
        h3 &= mask
        h0 = (h0 + 19 * (h4 >> 51)) % (2**64)
        h4 &= mask

        return fe25519([\
            ((self.ns[0] + 4503599627370458) - h0) % (2**64),
            ((self.ns[1] + 4503599627370494) - h1) % (2**64),
            ((self.ns[2] + 4503599627370494) - h2) % (2**64),
            ((self.ns[3] + 4503599627370494) - h3) % (2**64),
            ((self.ns[4] + 4503599627370494) - h4) % (2**64)
        ])

    def __mul__(self: fe25519, other: fe25519) -> fe25519:
        mask = 2251799813685247 # 64-bit integer.
        (f, g) = (self.ns, other.ns) # 64-bit integers.
        r = [None, None, None, None, None] # 128-bit integers.
        carry = None # 128-bit integer.
        r0 = [None, None, None, None, None] # 64-bit integers.

        f1_19 = (19 * f[1]) % (2**64)
        f2_19 = (19 * f[2]) % (2**64)
        f3_19 = (19 * f[3]) % (2**64)
        f4_19 = (19 * f[4]) % (2**64)

        r[0] = (f[0]*g[0] + f1_19*g[4] + f2_19*g[3] + f3_19*g[2] + f4_19*g[1]) % (2**128)
        r[1] = (f[0]*g[1] + f[1]*g[0] + f2_19*g[4] + f3_19*g[3] + f4_19*g[2]) % (2**128)
        r[2] = (f[0]*g[2] + f[1]*g[1] + f[2]*g[0] + f3_19*g[4] + f4_19*g[3]) % (2**128)
        r[3] = (f[0]*g[3] + f[1]*g[2] + f[2]*g[1] + f[3]*g[0] + f4_19*g[4]) % (2**128)
        r[4] = (f[0]*g[4] + f[1]*g[3] + f[2]*g[2] + f[3]*g[1] + f[4]*g[0]) % (2**128)

        r0[0] = (r[0] % (2**64)) & mask
        r[1] = (r[1] + (r[0] >> 51)) % (2**128)
        r0[1] = (r[1] % (2**64)) & mask
        r[2] = (r[2] + (r[1] >> 51)) % (2**128)
        r0[2] = (r[2] % (2**64)) & mask
        r[3] = (r[3] + (r[2] >> 51)) % (2**128)
        r0[3] = (r[3] % (2**64)) & mask
        r[4] = (r[4] + (r[3] >> 51)) % (2**128)
        r0[4] = (r[4] % (2**64)) & mask
        r0[0] = (r0[0] + (19*((r[4] >> 51) % (2**64)))) % (2**64)
        carry = r0[0] >> 51
        r0[0] &= mask
        r0[1] = (r0[1] + (carry % (2**64))) % (2**64)
        carry = r0[1] >> 51
        r0[1] &= mask
        r0[2] = (r0[2] + (carry % (2**64))) % (2**64)

        return fe25519(r0)

    def __pow__(self: fe25519, e: int) -> fe25519:
        if e == 2: # Squaring.
            mask = 2251799813685247 # 64-bit integer.
            f = self.ns # 64-bit integers.
            r = [None, None, None, None, None] # 128-bit integers.
            carry = None # 128-bit integer.
            r0 = [None, None, None, None, None] # 64-bit integers.

            f0_2 = (f[0] << 1) % (2**64)
            f1_2 = (f[1] << 1) % (2**64)

            f1_38 = (38 * f[1]) % (2**64)
            f2_38 = (38 * f[2]) % (2**64)
            f3_38 = (38 * f[3]) % (2**64)

            f3_19 = (19 * f[3]) % (2**64)
            f4_19 = (19 * f[4]) % (2**64)

            r[0] = (f[0]*f[0] + f1_38*f[4] + f2_38*f[3]) % (2**128)
            r[1] = (f0_2*f[1] + f2_38*f[4] + f3_19*f[3]) % (2**128)
            r[2] = (f0_2*f[2] + f[1]*f[1] + f3_38*f[4]) % (2**128)
            r[3] = (f0_2*f[3] + f1_2*f[2] + f4_19*f[4]) % (2**128)
            r[4] = (f0_2*f[4] + f1_2*f[3] + f[2]*f[2]) % (2**128)

            r0[0] = (r[0] % (2**64)) & mask
            r[1] = (r[1] + (r[0] >> 51)) % (2**128)
            r0[1] = (r[1] % (2**64)) & mask
            r[2] = (r[2] + (r[1] >> 51)) % (2**128)
            r0[2] = (r[2] % (2**64)) & mask
            r[3] = (r[3] + (r[2] >> 51)) % (2**128)
            r0[3] = (r[3] % (2**64)) & mask
            r[4] = (r[4] + (r[3] >> 51)) % (2**128)
            r0[4] = (r[4] % (2**64)) & mask
            r0[0] = (r0[0] + (19*((r[4] >> 51) % (2**64)))) % (2**64)
            carry = r0[0] >> 51
            r0[0] &= mask
            r0[1] = (r0[1] + (carry % (2**64))) % (2**64)
            carry = r0[1] >> 51
            r0[1] &= mask
            r0[2] = (r0[2] + (carry % (2**64))) % (2**64)

            return fe25519(r0)

        # Supplied exponent is not supported.
        return None

    def sq2(self: fe25519) -> fe25519:
        mask = 2251799813685247
        f = self.ns # 64-bit integers.
        r = [None, None, None, None, None] # 128-bit integers.
        carry = None # 128-bit integer.
        r0 = [None, None, None, None, None] # 64-bit integers.

        f0_2 = (f[0] << 1) % (2**64)
        f1_2 = (f[1] << 1) % (2**64)

        f1_38 = (38 * f[1]) % (2**64)
        f2_38 = (38 * f[2]) % (2**64)
        f3_38 = (38 * f[3]) % (2**64)

        f3_19 = (19 * f[3]) % (2**64)
        f4_19 = (19 * f[4]) % (2**64)

        r[0] = (f[0]*f[0] + f1_38*f[4] + f2_38*f[3]) % (2**128)
        r[1] = (f0_2*f[1] + f2_38*f[4] + f3_19*f[3]) % (2**128)
        r[2] = (f0_2*f[2] + f[1]*f[1] + f3_38*f[4]) % (2**128)
        r[3] = (f0_2*f[3] + f1_2*f[2] + f4_19*f[4]) % (2**128)
        r[4] = (f0_2*f[4] + f1_2*f[3] + f[2]*f[2]) % (2**128)

        r[0] <<= 1
        r[1] <<= 1
        r[2] <<= 1
        r[3] <<= 1
        r[4] <<= 1

        r0[0] = (r[0] % (2**64)) & mask
        carry  = r[0] >> 51
        r[1] = (r[1] + carry) % (2**128)
        r0[1] = (r[1] % (2**64)) & mask
        carry  = r[1] >> 51
        r[2] = (r[2] + carry) % (2**128)
        
        r0[2] = (r[2] % (2**64)) & mask
        carry = r[2] >> 51
        r[3] = (r[3] + carry) % (2**128)
        r0[3] = (r[3] % (2**64)) & mask
        carry = r[3] >> 51
        r[4] = (r[4] + carry) % (2**128)
        r0[4] = (r[4] % (2**64)) & mask
        carry = r[4] >> 51
        r0[0] = (r0[0] + 19*carry) % (2**64)
        carry = r0[0] >> 51
        r0[0] &= mask 
        r0[1] = (r0[1] + (carry % (2**64))) % (2**64)
        carry = r0[1] >> 51
        r0[1] &= mask
        r0[2] = (r0[2] + (carry % (2**64))) % (2**64)

        return fe25519(r0)

    def invert(self: fe25519) -> fe25519:
        z = self.copy()
        t0 = z ** 2
        t1 = t0 ** 2
        t1 = t1 ** 2
        t1 = z * t1
        t0 = t0 * t1
        t2 = t0 ** 2
        t1 = t1 * t2
        t2 = t1 ** 2
        for i in range(1,5):
            t2 = t2**2
        t1 = t2 * t1
        t2 = t1 ** 2
        for i in range(1,10):
            t2 = t2 ** 2
        t2 = t2 * t1
        t3 = t2 ** 2
        for i in range(1,20):
            t3 = t3 ** 2
        t2 = t3 * t2
        t2 = t2 ** 2
        for i in range(1,10):
            t2 = t2 ** 2
        t1 = t2 * t1
        t2 = t1 ** 2
        for i in range(1,50):
            t2 = t2 ** 2
        t2 = t2 * t1
        t3 = t2 ** 2
        for i in range(1,100):
            t3 = t3 ** 2
        t2 = t3 * t2
        t2 = t2 ** 2
        for i in range(1,50):
            t2 = t2 ** 2
        t1 = t2 * t1
        t1 = t1 ** 2
        for i in range(1,5):
            t1 = t1 ** 2
        return t1 * t0

    def pow22523(self: fe25519) -> fe25519:
        z = self.copy()
        t0 = z ** 2
        t1 = t0 ** 2
        t1 = t1 ** 2
        t1 = z * t1
        t0 = t0 * t1
        t0 = t0 ** 2
        t0 = t1 * t0
        t1 = t0 ** 2
        for i in range(1,5):
            t1 = t1 ** 2
        t0 = t1 * t0
        t1 = t0 ** 2
        for i in range(1,10):
            t1 = t1 ** 2
        t1 = t1 * t0
        t2 = t1 ** 2
        for i in range(1,20):
            t2 = t2 ** 2
        t1 = t2 * t1
        t1 = t1 ** 2
        for i in range(1,10):
            t1 = t1 ** 2
        t0 = t1 * t0
        t1 = t0 ** 2
        for i in range(1,50):
            t1 = t1 ** 2
        t1 = t1 * t0
        t2 = t1 ** 2
        for i in range(1,100):
            t2 = t2 ** 2
        t1 = t2 * t1
        t1 = t1 ** 2
        for i in range(1,50):
            t1 = t1 ** 2
        t0 = t1 * t0
        t0 = t0 ** 2
        t0 = t0 ** 2
        return t0 * z

    def __eq__(self: fe25519, other: fe25519) -> bool:
        return self.ns == other.ns

    def is_zero(self: fe25519) -> int:
        bs = self.to_bytes()
        d = 0
        for i in range(len(bs)):
            d |= bs[i]
        return 1 & ((d - 1) >> 8)

    def is_negative(self: fe25519) -> int:
        bs = self.to_bytes()
        return bs[0] & 1

    def cmov(self: fe25519, g: fe25519, b: int) -> fe25519:
        g = g.ns
        f = self.ns
        mask = (0 - b) % (2**64)
        
        x = [(f[i] ^ g[i]) & mask for i in range(5)]
        return fe25519([f[i] ^ x[i] for i in range(5)])

    @staticmethod
    def from_bytes(bs: bytes) -> fe25519:
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

        return fe25519([\
            (load64_le(bs[0:8])) & mask,
            (load64_le(bs[6:14]) >> 3) & mask,
            (load64_le(bs[12:20]) >> 6) & mask,
            (load64_le(bs[19:27]) >> 1) & mask,
            (load64_le(bs[24:32]) >> 12) & mask
        ])

    def to_bytes(self: fe25519) -> bytes:
        t = self.reduce().ns

        def store64_le(w):
            bs = bytearray()
            bs.append(w % 256)
            w >>= 8
            bs.append(w % 256)
            w >>= 8
            bs.append(w % 256)
            w >>= 8
            bs.append(w % 256)
            w >>= 8
            bs.append(w % 256)
            w >>= 8
            bs.append(w % 256)
            w >>= 8
            bs.append(w % 256)
            w >>= 8
            bs.append(w % 256)
            return bs

        t0 = t[0] | ((t[1] << 51)%(2**64))
        t1 = (t[1] >> 13) | ((t[2] << 38)%(2**64))
        t2 = (t[2] >> 26) | ((t[3] << 25)%(2**64))
        t3 = (t[3] >> 39) | ((t[4] << 12)%(2**64))

        bs = bytearray()
        bs.extend(store64_le(t0))
        bs.extend(store64_le(t1))
        bs.extend(store64_le(t2))
        bs.extend(store64_le(t3))
        return bs

    def __str__(self: fe25519) -> str:
        return 'fe25519(' + str(self.ns) + ')'

    def __repr__(self: fe25519) -> str:
        return str(self)

if __name__ == "__main__":
    doctest.testmod()
