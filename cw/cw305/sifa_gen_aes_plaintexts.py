#!/usr/bin/python3
# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

from Crypto.Cipher import AES
import argparse
import csv
import secrets
import re

parser = argparse.ArgumentParser(
    description=('Generator script for sequence of random AES '
                 'plainexts for Verilog testbench (together with key)'))
parser.add_argument('-k',
                    '--key',
                    dest='key',
                    metavar='key',
                    help=('Key hex input: 0x... '
                          '(byte order needs to be LITTLE ENDIAN)'),
                    default='0x00000000000000000000000000000000',
                    type=str,
                    required=False)
parser.add_argument('-s',
                    '--size',
                    dest='size',
                    metavar='size',
                    help='Key size input: 128, 192, 256',
                    choices=[128, 192, 256],
                    default=128,
                    type=int,
                    required=False)
parser.add_argument('-n',
                    '--num',
                    dest='num',
                    metavar='num',
                    help='Number of plaintexts to generate',
                    default=1024,
                    type=int,
                    required=False)
parser.add_argument('-d',
                    '--direction',
                    dest='direction',
                    metavar='direction',
                    help='Direction of AES: "enc", "dec"',
                    choices=['enc', 'dec'],
                    default='enc',
                    type=str,
                    required=False)
args = parser.parse_args()

with open('sifa_aes_input_verilator_sim.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    if args.direction == "enc":
        writer.writerow(["plaintext", "key", "expected ciphertext"])
    else:
        writer.writerow(["ciphertext", "key", "expected plaintext"])

    # Note that the byte order in OpenTitan AES is little endian
    cipher = AES.new((int(args.key, 16)).to_bytes(int(args.size / 8),
                                                  byteorder='little'),
                     AES.MODE_ECB)

    key = re.sub("0x", "", args.key)

    for i in range(args.num):
        rand16ByteHex = "0x" + secrets.token_hex(16)
        if args.direction == "enc":
            aes_out = cipher.encrypt(
                (int(rand16ByteHex, 16)).to_bytes(16, byteorder='little'))
        else:
            aes_out = cipher.decrypt(
                (int(rand16ByteHex, 16)).to_bytes(16, byteorder='little'))

        aesOutInt = int.from_bytes(aes_out, byteorder='little')
        aesOutStrHex = "%0.32x" % aesOutInt
        rand16ByteHex = re.sub("0x", "", rand16ByteHex)

        writer.writerow([rand16ByteHex, key, aesOutStrHex])