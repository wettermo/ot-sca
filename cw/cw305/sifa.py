# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0

import binascii
import numpy as np
import collections
import scipy
import copy
import random

import tqdm

import chipwhisperer as cw
from chipwhisperer.analyzer import aes_funcs


def sei(values):
   N=len(values)
   counter=collections.Counter(values)
   SEI = 0.0

   for i in range(256):
      SEI = SEI + (counter[i]/N - 1/256)**2
   
   return SEI

def calc_affected_bytes9(index):
   '''calc_affected_bytes9()

   takes as input index 0-15 of the AES state
   returns index of affected bytes if one byte is faulted
   in subbyte of round 9
   possible return values are:
   [0, 7, 10, 13]
   [3, 6,  9, 12]
   [2, 5,  8, 15]
   [1, 4, 11, 14]
   '''

   state = [0] * 16
   state[index] = 1
   state = aes_funcs.shiftrows(state)
   state = aes_funcs.mixcolumns(state)
   #subbytes does not change layout
   #addrk does not change layout
   state = aes_funcs.shiftrows(state)
   #return index of non zero element
   return [i for i, e in enumerate(state) if e != 0]

def bin_format(integer):
   return f'{integer:0>8b}'

def hex_format(integer):
   return f'{integer:0>2X}'

def fault_model(byte_in, fault_type):
   if fault_type == "stuck_at_2zero":
      return byte_in & 0b00111111
   elif fault_type == "stuck_at_1zero":
      return byte_in & 0b01111111
   elif fault_type == "stuck_at_2one":
      return byte_in | 0b11000000
   elif fault_type == "random_byteand":
      random_byte = random.randint(0, 255)
      return byte_in & random_byte
   elif fault_type == "random_2or":
      random_2bit = random.randint(0, 3)
      return byte_in | random_2bit
   
   print("Warning no fault selected!")
   return byte_in

def print_state(state):
   hexstate = binascii.b2a_hex(bytes(state))
   binstate = list(map(bin_format,state))
   #print(state, hexstate, binstate)
   print(binstate)

def ifprint(en, text, state):
   if en :
      hexstate = list(map(hex_format,state))
      binstate = list(map(bin_format,state))
      print(text, hexstate)

def decrypt_stepwise(ciphertext, key, exit_tuple=(0, 'addkey')):

   if exit_tuple == (10, 'inv_mixcolums'):
      raise ValueError("no inv_mixcolums in round 10!")

   if ((exit_tuple[0] == 0) and (exit_tuple[1] != 'addkey')):
      raise ValueError("round 0 only consists of addkey")

   if exit_tuple[0] not in range(0,11):
      raise ValueError("round number must be in [0,10]")

   if exit_tuple[1] not in ['addkey', 'inv_shiftrows', 'inv_mixcolums', 'inv_subbytes']:
      raise ValueError("AES-Operation must be 'addkey', 'inv_shiftrows', 'inv_mixcolums', 'inv_subbytes'")

   state = np.array(copy.deepcopy(ciphertext))
   #round 10
   rk_10 = np.array(aes_funcs.key_schedule_rounds(key, 0, 10))
   state = state ^ rk_10 
   if exit_tuple == (10, 'addkey'): return state.tolist()
   state = aes_funcs.inv_shiftrows(state.tolist())
   if exit_tuple == (10, 'inv_shiftrows'): return state
   state = aes_funcs.inv_subbytes(state)
   if exit_tuple == (10, 'inv_subbytes'): return state

   #round 9 to 1
   for i in range(9, 0, -1): 
      state = np.array(state)
      state = state ^ np.array(aes_funcs.key_schedule_rounds(key, 0, i))
      if exit_tuple == (i, 'addkey'): return state.tolist()
      state = aes_funcs.inv_mixcolumns(state.tolist())
      if exit_tuple == (i, 'inv_mixcolums'): return state
      state = aes_funcs.inv_shiftrows(state)
      if exit_tuple == (i, 'inv_shiftrows'): return state
      state = aes_funcs.inv_subbytes(state)
      if exit_tuple == (i, 'inv_subbytes'): return state

   # round 0
   state = np.array(state)
   state = state ^ np.array(aes_funcs.key_schedule_rounds(key, 0, 0))

   return state.tolist()

def encrypt_stepwise(plaintext, key, exit_tuple=(10, 'addkey'), faulted_byte_index = 0, fault=False, fault_type='stuck_at_2zero',debug=False):

   if exit_tuple == (10, 'mixcolums'):
      raise ValueError("no mixcolums in round 10!")

   if ((exit_tuple[0] == 0) and (exit_tuple[1] != 'addkey')):
      raise ValueError("round 0 only consists of addkey")

   if exit_tuple[0] not in range(0,11):
      raise ValueError("round number must be in [0,10]")

   if exit_tuple[1] not in ['addkey', 'shiftrows', 'mixcolums', 'subbytes']:
      raise ValueError("AES-Operation must be 'addkey', 'shiftrows', 'mixcolums', 'subbytes'")


   # round 0
   state = np.array(copy.deepcopy(plaintext))
   ifprint(debug, "Plaintext         ", state.tolist())
   rk_0 = np.array(aes_funcs.key_schedule_rounds(key, 0, 0))
   ifprint(debug, "RK               0" , rk_0.tolist())

   state = state ^ rk_0
   ifprint(debug, "After RK         0", state.tolist())
   if exit_tuple == (0, 'addkey'): return state.tolist()

   #round 1 to 9
   for i in range(1,10,1): 
      state = aes_funcs.subbytes(state.tolist())
      if (i == 9 and fault == True):
         state[faulted_byte_index] = fault_model(state[faulted_byte_index], fault_type)

      ifprint(debug, "After subbyte    "+str(i), state)
      if exit_tuple == (i, 'subbytes'): return state
      state = aes_funcs.shiftrows(state)
      ifprint(debug, "After shiftrows  "+str(i), state)
      if exit_tuple == (i, 'shiftrows'): return state
      state = aes_funcs.mixcolumns(state)
      ifprint(debug, "After mixcolums  "+str(i), state)
      if exit_tuple == (i, 'mixcolums'): return state

      state = np.array(state)
      rk = np.array(aes_funcs.key_schedule_rounds(key, 0, i))
      state = state ^ rk
      ifprint(debug, "RK               "+str(i), rk.tolist())

      ifprint(debug, "After RK         "+str(i), state.tolist())
      if exit_tuple == (i, 'addkey'): return state.tolist()

   #round 10
   state = aes_funcs.subbytes(state.tolist())
   ifprint(debug, "After subbyte   10", state)
   if exit_tuple == (10, 'subbytes'): return state
   state = aes_funcs.shiftrows(state)
   ifprint(debug, "After shiftrows 10", state)
   if exit_tuple == (10, 'shiftrows'): return state

   state = np.array(state)
   rk = np.array(aes_funcs.key_schedule_rounds(key, 0, 10))
   state = state ^ rk
   ifprint(debug, "RK              10", rk.tolist())
   ifprint(debug, "After RK        10", state.tolist())
   ifprint(debug, "Ciphertext        ", state.tolist())

   return state.tolist()

def encrypt(plaintext, key):
   return encrypt_stepwise(plaintext, key, (10, 'addkey'), 0, False)

def encrypt_fault(plaintext, key, faulted_byte_index, faulted_round=9,fault_type='stuck_at_zero'):
   if faulted_round != 9:
      print("Error, only faults in round9 are supported")
      exit(1)
   if fault_type not in ['stuck_at_2zero', 'stuck_at_1zero', 'stuck_at_2one', 'random_byteand', 'random_2or']:
      print("Error, fault type not supported")
      exit(1)
   return encrypt_stepwise(plaintext, key, (10, 'addkey'), faulted_byte_index, True, fault_type)

def decrypt(ciphertext, key):
   return decrypt_stepwise(ciphertext, key, (0, 'addkey'))

def verify_ciphertext(ineff_ciphertexts, ineff_plaintexts, known_key):
   progress_bar = tqdm.tqdm(total=len(ineff_ciphertexts), ncols=80)
   progress_bar.set_description('Verifing ciphertext-plaintext pairs')
   for i in range(len(ineff_ciphertexts)):
      got = decrypt(ineff_ciphertexts[i], known_key)
      expected = ineff_plaintexts[i]
      got_hex= binascii.b2a_hex(bytes(got))
      expected_hex= binascii.b2a_hex(expected)
      if got_hex != expected_hex:
         print("Error: something is wrong with the data")
         exit(1)
      progress_bar.update()
   progress_bar.close()   
   print ("...everything is fine")


def sim_data(faulted_byte_index, fault_type, numb_runs):
   ktp = cw.ktp.Basic()
   ktp.key_len = 16
   ktp.text_len = 16

   key, _ = ktp.next() # key.next() generator is constant!
   eff_faults = 0
   ineff_faults = 0
   ineff_ciphertexts = []
   ineff_plaintexts = []

   progress_bar = tqdm.tqdm(total=numb_runs, ncols=80)
   progress_bar.set_description('Simulating faulty encryptions')

   for i in range (numb_runs):
      _, text = ktp.next()
      ciphertext = encrypt_fault(list(text),list(key),faulted_byte_index, 9, fault_type)
      plaintext = decrypt(ciphertext,list(key))
   
      if plaintext == list(text):
         ineff_faults+=1
         ineff_ciphertexts.append(ciphertext)
         ineff_plaintexts.append(plaintext)
      else:
         eff_faults+=1
      progress_bar.update()

   progress_bar.close()

   total_faults = ineff_faults+eff_faults
   print("Effective faults:  ", eff_faults)
   print("Ineffective faults:", ineff_faults)
   print("Total Faults:      ", total_faults)
   print("Ineffective rate:  ", ineff_faults/total_faults)

   return ineff_ciphertexts, ineff_plaintexts, key

def fault_ciphertexts_from_plaintext(faulted_byte_index, fault_type, numb_runs, plaintexts, key):
   eff_faults = 0
   ineff_faults = 0
   ineff_ciphertexts = []
   ineff_plaintexts = []

   progress_bar = tqdm.tqdm(total=numb_runs, ncols=80)
   progress_bar.set_description('Simulating faulty encryptions')

   for i in range (numb_runs):
      text = plaintexts[i]
      ciphertext = encrypt_fault(list(text),list(key),faulted_byte_index, 9, fault_type)
      plaintext = decrypt(ciphertext,list(key))
   
      if plaintext == list(text):
         ineff_faults+=1
         ineff_ciphertexts.append(ciphertext)
         ineff_plaintexts.append(plaintext)
      else:
         eff_faults+=1
      progress_bar.update()

   progress_bar.close()

   total_faults = ineff_faults+eff_faults
   print("Effective faults:  ", eff_faults)
   print("Ineffective faults:", ineff_faults)
   print("Total Faults:      ", total_faults)
   print("Ineffective rate:  ", ineff_faults/total_faults)

   return ineff_ciphertexts, ineff_plaintexts, key

