#!/usr/bin/env python3
# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0


import sifa
from vendor.lowrisc_opentitan import create_tlul_sequence
import numpy as np
import chipwhisperer as cw
from chipwhisperer.analyzer import aes_funcs


fault_type = 'stuck_at_2zero'
faulted_byte_index = 0
attackable_key_byte_index = sifa.calc_affected_bytes9(faulted_byte_index)
attacked_key_byte_index = attackable_key_byte_index[0] #[0,1,2,3]


# ==== use pre-calculated values === #
#ineff_ciphertexts = [[92, 234, 191, 5, 228, 156, 66, 56, 57, 244, 168, 162, 91, 46, 14, 252]]
#ineff_plaintexts = [[225, 245, 50, 91, 220, 63, 92, 99, 75, 233, 128, 60, 196, 100, 148, 200]]
#known_key=[43, 126,  21,  22,  40, 174, 210, 166, 171, 247,  21, 136,   9, 207,  79,  60]

# ==== get data from external measurement ==== #

########################################################################################
### CAUTION: MAKE ABSOLUTLY SURE THAT YOU USE THE RIGHT AES-PARAMETERS FOR SYNTHESIS ###
###          IT IS **NOT** SUFFICIANT TO CHANGE THE PARAMETERS IN THE .hjson-FILES   ###
###                                                                                  ###
###          For chip_cw310 they are hardcoded in topgen.py                          ###
###                                                                                  ###
###          YOU MUST EITHER CHANGE THE PARAMETERS IN                                ###
###                 - hw/top_earlgrey/rtl/autogen/chip_earlgrey_cw310.sv  or         ###
###                 - util/topgen/templates/chiplevel.sv.tpl                         ###
###                                                                                  ###
########################################################################################


project_file = "projects/sifa_aes_9sbox_2b0"
project = cw.open_project(project_file)

numb_ciphertexts = 100
known_key = project.keys[0]
ineff_ciphertexts = project.textouts[0:numb_ciphertexts]
ineff_plaintexts = project.textins[0:numb_ciphertexts]

# ==== get data from simulation ==== #
#runs= 100
#ineff_ciphertexts, ineff_plaintexts, known_key = sifa.sim_data(faulted_byte_index, fault_type, runs)

# ==== write data to verilator simulation ==== #
ot_repo = "/home/tempelmm/gits/opentitan/"
sequence_file= ot_repo+"hw/ip/aes/pre_dv/aes_tb/cpp/aes_tlul_sequence_auto.h"
create_tlul_sequence.create_sequence(ineff_plaintexts, ineff_ciphertexts, known_key, 25, sequence_file)


# ==== some routines to debug things ===== #
# This should have a ineffective rate of 100% if not, your plaintext set contains effective faults!
#ineff_ciphertexts, ineff_plaintexts, known_key = sifa.fault_ciphertexts_from_plaintext(faulted_byte_index ,"stuck_at_2zero", numb_ciphertexts, ineff_plaintexts, known_key)

# displays the state after the attack
print("State after subbytes in Round 9")
for i in ineff_plaintexts[0:numb_ciphertexts]:
   print(list(map(sifa.hex_format,sifa.encrypt_stepwise(i, known_key, (9, 'subbytes'), fault=fault_type,debug= False))))
