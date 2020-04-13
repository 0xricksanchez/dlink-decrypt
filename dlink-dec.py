#!/usr/bin/env python3

import sys
import hashlib
import binascii
import pathlib
import argparse
import struct
import os

from contextlib import suppress
from Crypto.Cipher import AES

CIPHERTEXT_OFF = 0x6DC
SHA512_DEC_FW_W_KEY_OFF = 0x1C
SHA512_DEC_FW = 0x5C
SHA512_ENC_FW = 0x9C
IVEC_OFF = 0xC
DATA_LEN_DEC_FW_OFF = 0x4
DATALEN_DEC_FW_NO_PADDING_OFF = 0x8
IVEC_LEN = 0x10
DATA_LEN = 0x4


class DcryptLink:
    def __init__(self, inp, outp, mode):
        self.inp = inp
        self.outp = outp
        self.key = None
        self.data_len_dec_fw_no_padding = None
        self.data_len_dec_fw = None
        self.ivec = None
        self.mode = mode
        self.__setup__()

    def __setup__(self):
        self.set_key()
        self.set_datalen_variables()
        self.set_ivec()

    def run(self):
        if self.mode == "dec":
            self.decrypt()
        else:
            self.encrypt()

    @staticmethod
    def get_expected_sha512_from_fd_at_offset(file, offset, size=0x40):
        with open(file, "rb") as enc_fw:
            enc_fw.seek(offset)
            return binascii.hexlify(enc_fw.read(size)).decode()

    @staticmethod
    def calc_sha512_from_fd_at_offset_of_len(file, offset_payload, len_payload, key=None):
        with open(file, "rb") as enc_fw:
            enc_fw.seek(offset_payload)
            data = enc_fw.read(len_payload)
            if key:
                data = data + key
        return hashlib.sha512(data).hexdigest()

    @staticmethod
    def verify(calculated, expected):
        if expected != calculated:
            print("\t[!] Failed!")
            raise ValueError
        print("\t[+] OK!")
        return 0

    def decrypt_aes128_cbc(self):
        with open(self.inp, "rb") as enc_fw:
            enc_fw.seek(CIPHERTEXT_OFF)
            ciphertext = enc_fw.read(self.data_len_dec_fw_no_padding)
        cipher = AES.new(self.key, AES.MODE_CBC, self.ivec)
        plaintext = cipher.decrypt(ciphertext)
        pathlib.Path(self.outp).open("wb").write(plaintext)

    def verify_magic_bytes(self):
        expected = b"SHRS"
        actual = pathlib.Path(self.inp).open("rb").read(4)
        print("[*] Checking magic bytes...")
        self.verify(actual, expected)

    def set_datalen_variables(self):
        with open(self.inp, "rb") as enc_fw:
            enc_fw.seek(DATA_LEN_DEC_FW_OFF)
            self.data_len_dec_fw = int.from_bytes(enc_fw.read(DATA_LEN), byteorder="big", signed=False)
            enc_fw.seek(DATALEN_DEC_FW_NO_PADDING_OFF)
            self.data_len_dec_fw_no_padding = int.from_bytes(enc_fw.read(DATA_LEN), byteorder="big", signed=False)

    def set_ivec(self):
        with open(self.inp, "rb") as enc_fw:
            enc_fw.seek(IVEC_OFF)
            self.ivec = enc_fw.read(IVEC_LEN)

    def set_key(self):
        in_file = bytes.fromhex("C8D32F409CACB347C8D26FDCB9090B3C")
        user_key = bytes.fromhex("358790034519F8C8235DB6492839A73F")
        ivec = bytes.fromhex("98C9D8F0133D0695E2A709C8B69682D4")

        print("[*] Calculating key...")

        self.key = AES.new(user_key, AES.MODE_CBC, ivec).decrypt(in_file)
        self.verify(self.key, bytes.fromhex("C05FBF1936C99429CE2A0781F08D6AD8"))

    def decrypt(self):

        self.verify_magic_bytes()

        print("[*] Verifying SHA512 message digest of encrypted payload...")
        md = self.calc_sha512_from_fd_at_offset_of_len(self.inp, CIPHERTEXT_OFF, self.data_len_dec_fw_no_padding)
        expected_md = self.get_expected_sha512_from_fd_at_offset(self.inp, SHA512_ENC_FW)
        self.verify(md, expected_md)

        self.decrypt_aes128_cbc()

        print("[*] Verifying SHA512 message digests of decrypted payload...")
        md = self.calc_sha512_from_fd_at_offset_of_len(self.outp, 0, self.data_len_dec_fw)
        expected_md = self.get_expected_sha512_from_fd_at_offset(self.inp, SHA512_DEC_FW)
        self.verify(md, expected_md)

        md = self.calc_sha512_from_fd_at_offset_of_len(self.outp, 0, self.data_len_dec_fw, key=self.key)
        expected_md = self.get_expected_sha512_from_fd_at_offset(self.inp, SHA512_DEC_FW_W_KEY_OFF)
        self.verify(md, expected_md)

        print(f'[+] Successfully decrypted "{pathlib.Path(self.inp).name}"!')

    def encrypt(self):
        # self.ivec can also be set to os.urandom(16) and encryption still works for arbitrary binaries.
        # 67..46 was chosen to handle original D-Link firmware files
        self.ivec = bytes.fromhex("67C6697351FF4AEC29CDBAABF2FBE346")

        data = pathlib.Path(self.inp).read_bytes()
        self.data_len_dec_fw_no_padding = len(data)

        if self.data_len_dec_fw_no_padding % 16 != 0:
            data += data + b"\x00" * (16 - self.data_len_dec_fw_no_padding % 16)
            self.data_len_dec_fw = len(data)
        else:
            self.data_len_dec_fw = self.data_len_dec_fw_no_padding

        print("[*] Calculating cipher...")
        ciphert = AES.new(self.key, AES.MODE_CBC, self.ivec).encrypt(data)

        print("[*] Building essential security header...")
        sec_header = b"SHRS"
        sec_header += struct.pack(">I", self.data_len_dec_fw_no_padding)
        sec_header += struct.pack(">I", self.data_len_dec_fw)
        sec_header += self.ivec
        sec_header += bytes.fromhex(
            self.calc_sha512_from_fd_at_offset_of_len(self.inp, 0, self.data_len_dec_fw_no_padding, key=self.key)
        )
        sec_header += bytes.fromhex(self.calc_sha512_from_fd_at_offset_of_len(self.inp, 0, self.data_len_dec_fw_no_padding))
        sec_header += bytes.fromhex(hashlib.sha512(ciphert).hexdigest())
        sec_header += b"\x00" * 512
        sec_header += os.urandom(512)  # fake signature1, and
        sec_header += os.urandom(512)  # fake signature2 as they're not needed for decryption..

        print("[*] Writing encrypted firmware to file...")
        pathlib.Path(self.outp).write_bytes(sec_header + ciphert)
        print("\t[+] Done!")


def main():
    arg_parser = argparse.ArgumentParser(
        description="D-Link SHRS decyption tool", formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    arg_parser.add_argument("-i", "--inp", type=str, help="Path to the encrypted D-Link firmware image", required=True)
    arg_parser.add_argument("-o", "--out", type=str, help="Path to the decrypted firmware image", required=True)
    arg_parser.add_argument(
        "-m", "--mode", type=str, default="dec", choices=["dec", "enc"], help="Choose whether to encrypt or decrypt",
    )
    cli_args = arg_parser.parse_args()

    dlink = DcryptLink(cli_args.inp, cli_args.out, cli_args.mode)

    try:
        dlink.run()
    except ValueError:
        with suppress(FileNotFoundError):
            pathlib.Path(dlink.outp).unlink()
        print("[!] Failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
