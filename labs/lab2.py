import math
import struct

class MD5:
    def __init__(self):
        self.A = 0x67452301
        self.B = 0xEFCDAB89
        self.C = 0x98BADCFE
        self.D = 0x10325476

        self.shift_amounts = [
            [7, 12, 17, 22],
            [5, 9, 14, 20],
            [4, 11, 16, 23],
            [6, 10, 15, 21]
        ]

        self.K = [int(abs(math.sin(i + 1)) * (2 ** 32)) & 0xFFFFFFFF for i in range(64)]

    def rotate(self, x, c):
        x &= 0xFFFFFFFF
        return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF

    def hash_string(self, message_string):
        return self.hash_bytes(message_string.encode('utf-8'))

    def hash_file(self, filename):
        try:
            with open(filename, 'rb') as f:
                data = f.read()
            return self.hash_bytes(data)
        except FileNotFoundError:
            return "File not found!"

    def hash_bytes(self, message):
        orig_len_in_bits = (8 * len(message)) & 0xffffffffffffffff
        message += b'\x80'

        while len(message) % 64 != 56:
            message += b'\x00'

        message += struct.pack('<Q', orig_len_in_bits)

        for i in range(0, len(message), 64):
            chunk = message[i:i + 64]
            M = list(struct.unpack('<16I', chunk))

            A, B, C, D = self.A, self.B, self.C, self.D

            for j in range(64):
                round_idx = j // 16
                shift_idx = j % 4
                s = self.shift_amounts[round_idx][shift_idx]

                if 0 <= j <= 15:
                    F = (B & C) | (~B & D)
                    g = j
                elif 16 <= j <= 31:
                    F = (D & B) | (~D & C)
                    g = (5 * j + 1) % 16
                elif 32 <= j <= 47:
                    F = B ^ C ^ D
                    g = (3 * j + 5) % 16
                elif 48 <= j <= 63:
                    F = C ^ (B | ~D)
                    g = (7 * j) % 16

                F = (F + A + self.K[j] + M[g]) & 0xFFFFFFFF
                A = D
                D = C
                C = B
                B = (B + self.rotate(F, s)) & 0xFFFFFFFF

            self.A = (self.A + A) & 0xFFFFFFFF
            self.B = (self.B + B) & 0xFFFFFFFF
            self.C = (self.C + C) & 0xFFFFFFFF
            self.D = (self.D + D) & 0xFFFFFFFF

        result = struct.pack('<4I', self.A, self.B, self.C, self.D)
        return result.hex()