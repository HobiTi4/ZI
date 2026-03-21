import struct
import os
from labs.lab1 import LCG
from labs.lab2 import MD5


class RC5:
    def __init__(self, w, r, key_bytes):
        self.w = w
        self.r = r
        self.key = key_bytes
        self.mod = 2 ** w
        self.mask = self.mod - 1
        self.b = len(key_bytes)

        if w == 16:
            self.P, self.Q = 0xB7E1, 0x9E37
        elif w == 32:
            self.P, self.Q = 0xB7E15163, 0x9E3779B9
        elif w == 64:
            self.P, self.Q = 0xB7E151628AED2A6B, 0x9E3779B97F4A7C15
        else:
            raise ValueError("Unsupported word size w")

        self.S = self._key_expansion()

    def _rotate_left(self, val, shift):
        shift %= self.w
        return ((val << shift) & self.mask) | ((val & self.mask) >> (self.w - shift))

    def _rotate_right(self, val, shift):
        shift %= self.w
        return ((val & self.mask) >> shift) | ((val << (self.w - shift)) & self.mask)

    def _key_expansion(self):
        u = self.w // 8
        c = max(1, (self.b + u - 1) // u)
        L = [0] * c

        for i in range(self.b):
            L[i // u] += self.key[i] << (8 * (i % u))

        t = 2 * self.r + 2
        S = [0] * t
        S[0] = self.P
        for i in range(1, t):
            S[i] = (S[i - 1] + self.Q) & self.mask

        i = j = A = B = 0
        for _ in range(3 * max(t, c)):
            A = S[i] = self._rotate_left((S[i] + A + B) & self.mask, 3)
            B = L[j] = self._rotate_left((L[j] + A + B) & self.mask, A + B)
            i = (i + 1) % t
            j = (j + 1) % c

        return S

    def encrypt_block(self, A, B):
        A = (A + self.S[0]) & self.mask
        B = (B + self.S[1]) & self.mask
        for i in range(1, self.r + 1):
            A = (self._rotate_left(A ^ B, B) + self.S[2 * i]) & self.mask
            B = (self._rotate_left(B ^ A, A) + self.S[2 * i + 1]) & self.mask
        return A, B

    def decrypt_block(self, A, B):
        for i in range(self.r, 0, -1):
            B = self._rotate_right((B - self.S[2 * i + 1]) & self.mask, A) ^ A
            A = self._rotate_right((A - self.S[2 * i]) & self.mask, B) ^ B
        B = (B - self.S[1]) & self.mask
        A = (A - self.S[0]) & self.mask
        return A, B


def derive_key(password, b):
    md5 = MD5()
    h1_hex = md5.hash_string(password)
    h1 = bytes.fromhex(h1_hex)

    if b <= 16:
        return h1[:b]
    elif b == 32:
        h2_hex = md5.hash_bytes(h1)
        h2 = bytes.fromhex(h2_hex)
        return h2 + h1
    else:
        return (h1 * (b // 16 + 1))[:b]


def generate_iv(size):
    x0 = int.from_bytes(os.urandom(4), 'little')
    lcg = LCG(m=2 ** 31 - 1, a=16807, c=0, x0=x0)

    iv = bytearray()
    for _ in range(size):
        iv.append(lcg.next() % 256)
    return bytes(iv)


def rc5_cbc_pad_encrypt(input_path, output_path, password, w=16, r=8, b=16):
    key = derive_key(password, b)
    rc5 = RC5(w, r, key)

    block_size = (2 * w) // 8
    if w == 16:
        format_str = '<2H'
    elif w == 32:
        format_str = '<2I'
    elif w == 64:
        format_str = '<2Q'
    else:
        raise ValueError("Unsupported word size")

    iv = generate_iv(block_size)
    iv_A, iv_B = struct.unpack(format_str, iv)
    enc_iv_A, enc_iv_B = rc5.encrypt_block(iv_A, iv_B)

    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        f_out.write(struct.pack(format_str, enc_iv_A, enc_iv_B))

        prev_A, prev_B = enc_iv_A, enc_iv_B

        while True:
            chunk = f_in.read(block_size)
            if len(chunk) < block_size:
                pad_len = block_size - len(chunk)
                chunk += bytes([pad_len] * pad_len)

                A, B = struct.unpack(format_str, chunk)
                A, B = A ^ prev_A, B ^ prev_B
                enc_A, enc_B = rc5.encrypt_block(A, B)
                f_out.write(struct.pack(format_str, enc_A, enc_B))
                break

            A, B = struct.unpack(format_str, chunk)
            A, B = A ^ prev_A, B ^ prev_B
            enc_A, enc_B = rc5.encrypt_block(A, B)
            f_out.write(struct.pack(format_str, enc_A, enc_B))
            prev_A, prev_B = enc_A, enc_B


def rc5_cbc_pad_decrypt(input_path, output_path, password, w=16, r=8, b=16):
    key = derive_key(password, b)
    rc5 = RC5(w, r, key)

    block_size = (2 * w) // 8

    if w == 16:
        format_str = '<2H'
    elif w == 32:
        format_str = '<2I'
    elif w == 64:
        format_str = '<2Q'
    else:
        raise ValueError("Unsupported word size")

    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        iv_chunk = f_in.read(block_size)
        enc_iv_A, enc_iv_B = struct.unpack(format_str, iv_chunk)
        prev_A, prev_B = enc_iv_A, enc_iv_B

        decrypted_data = bytearray()

        while True:
            chunk = f_in.read(block_size)
            if not chunk:
                break

            enc_A, enc_B = struct.unpack(format_str, chunk)
            dec_A, dec_B = rc5.decrypt_block(enc_A, enc_B)

            A, B = dec_A ^ prev_A, dec_B ^ prev_B
            decrypted_data.extend(struct.pack(format_str, A, B))

            prev_A, prev_B = enc_A, enc_B

        if decrypted_data:
            pad_len = decrypted_data[-1]

            if pad_len == 0 or pad_len > block_size:
                raise ValueError("Wrong password or corrupted file! (Invalid padding length)")

            for i in range(1, pad_len + 1):
                if decrypted_data[-i] != pad_len:
                    raise ValueError("Wrong password! (Padding bytes mismatch)")

            decrypted_data = decrypted_data[:-pad_len]

        f_out.write(decrypted_data)