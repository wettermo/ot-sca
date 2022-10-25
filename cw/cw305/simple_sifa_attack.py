#!/usr/bin/env python3
# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

from copy import deepcopy
import matplotlib.pyplot as plt
import binascii
import argparse
import sifa
import tqdm
import numpy as np
import chipwhisperer as cw
from chipwhisperer.analyzer import aes_funcs

parser = argparse.ArgumentParser(
    description='Simple SIFA attack on the AES inside the OpenTitan Chip')
parser.add_argument('-ft',
                    '--fault-type',
                    dest='f_type',
                    metavar='f_type',
                    help=('Fault type: "stuck_at_2zero", "stuck_at_1zero", '
                          '"stuck_at_2one", "random_byteand", "random_2or"'),
                    choices=[
                        'stuck_at_2zero', 'stuck_at_1zero', 'stuck_at_2one',
                        'random_byteand', 'random_2or'
                    ],
                    default='stuck_at_2zero',
                    type=str,
                    required=False)
parser.add_argument('-fi',
                    '--fault-index',
                    dest='f_index',
                    metavar='f_index',
                    help='Fault index: 0, 1, 2, ...',
                    default=0,
                    type=int,
                    required=False)
parser.add_argument('-k',
                    '--key',
                    dest='key',
                    metavar='key',
                    help=('Specific key hex input: 0x... '
                          '(byte order needs to be LITTLE ENDIAN)'),
                    default='0x00',
                    type=str,
                    required=False)
parser.add_argument('-a',
                    '--attack',
                    dest='attack',
                    metavar='attack',
                    help='Attack type: "fpga", "verilator", "python"',
                    choices=['fpga', 'verilator', 'python'],
                    default='verilator',
                    type=str,
                    required=False)
parser.add_argument('-s',
                    '--synthesized',
                    dest='synthesized',
                    help=('If specified Verilator attack uses ciphertext'
                          'data from synthesized netlist simulation'),
                    action='store_true',
                    default=False,
                    required=False)
args = parser.parse_args()

fault_type = args.f_type
faulted_byte_index = args.f_index
attackable_key_byte_index = sifa.calc_affected_bytes9(faulted_byte_index)
attacked_key_byte_index = attackable_key_byte_index[0]  #[0,1,2,3]

# ==== get data from external measurement ==== #
if args.attack == 'fpga':
    project_file = "projects/sifa_aes_9sbox_2b0"
    project = cw.open_project(project_file)

    numb_ciphertexts = 100
    known_key = project.keys[0]
    ineff_ciphertexts = project.textouts[0:numb_ciphertexts]
    ineff_plaintexts = project.textins[0:numb_ciphertexts]

# ==== get data from verilator simulation ==== #
elif args.attack == 'verilator':
    if args.synthesized == True:
        print('Using results of synthesized Verilator simulation')
        verilator_out_file = 'sifa_aes_syn_output_verilator_sim.csv'
    else:
        print('Using results of standard Verilator simulation')
        verilator_out_file = 'sifa_aes_output_verilator_sim.csv'
    ineff_ciphertexts, ineff_plaintexts, known_key = sifa.verilator_sim_data(
        verilator_out_file)

# ==== get data from python simulation ==== #
elif args.attack == 'python':
    runs = 100
    ineff_ciphertexts, ineff_plaintexts, known_key = sifa.sim_data(
        faulted_byte_index, fault_type, runs)

else:
    print("No attack specified, aborting...")
    exit()

if len(ineff_ciphertexts) == 0 or len(ineff_plaintexts) == 0:
    print("No ineffective faults found, aborting...")
    exit()

# ==== attack ==== #
rk_10 = np.array(aes_funcs.key_schedule_rounds(list(known_key), 0, 10))
rk_10_attacked_value = rk_10[attacked_key_byte_index]
print("using RK10: ", rk_10)
all_attacked_bytes = []
progress_bar = tqdm.tqdm(total=len(ineff_ciphertexts), ncols=80)
progress_bar.set_description('Performing attack')
for textout in ineff_ciphertexts:
    attacked_byte = []
    for keyguess in range(256):
        rk_10[attacked_key_byte_index] = keyguess

        state = np.array(textout)
        #round 10
        state = state ^ rk_10
        state = aes_funcs.inv_shiftrows(state.tolist())
        state = aes_funcs.inv_subbytes(state)
        #round 9
        # add round key 9 can be ignored, as it does not change the distribution
        state = np.array(state)
        state = aes_funcs.inv_mixcolumns(state.tolist())
        state = aes_funcs.inv_shiftrows(state)
        # we are attacking the output of the S-Box, but subbyte shouldn't change
        # the distribution either
        attacked_byte.append(state[faulted_byte_index])
    all_attacked_bytes.append(attacked_byte)
    progress_bar.update()

progress_bar.close()

all_attacked_bytes_matrix = np.array(all_attacked_bytes)

all_sei_values = []
for keyguess in range(256):
    sei_value = sifa.sei(all_attacked_bytes_matrix[:, keyguess])
    all_sei_values.append(sei_value)

guessed_key = np.argmax(all_sei_values)

print("Keybyte", attacked_key_byte_index, "of round 10 is most likely",
      guessed_key)
print("Keybyte", attacked_key_byte_index, "of round 10 is actaually  ",
      rk_10_attacked_value)

if (guessed_key !=
        rk_10_attacked_value) or True:  # temporarly always display plot
    # we couldn't guess the key, let's have a look at the plot
    plt.scatter(list(range(256)), all_sei_values)
    plt.show()
