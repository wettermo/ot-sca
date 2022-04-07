#!/usr/bin/env python3
# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
import argparse
import binascii
from Crypto.Cipher import AES
import numpy as np
import time
from tqdm import tqdm
import yaml
from types import SimpleNamespace
import typer
from pathlib import Path

import chipwhisperer as cw

from util import device
from pyXKCP import pyxkcp
import sifa


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


app = typer.Typer(add_completion=False)
# To be able to define subcommands for the "capture" command.
app_capture = typer.Typer()
app.add_typer(app_capture, name="capture", help="Capture traces for SCA")
# Shared options for "capture aes" and "capture sha3".
opt_num_traces = typer.Option(None, help="Number of traces to capture.")



# Note: initialize_capture and are also used by other scripts.
def initialize_capture(device_cfg, capture_cfg):
    """Initialize capture."""
    ot = device.OpenTitan(device_cfg["fpga_bitstream"],
                          device_cfg["fw_bin"],
                          device_cfg["pll_frequency"],
                          device_cfg["baudrate"],
                          capture_cfg["scope_gain"],
                          capture_cfg["num_samples"],
                          capture_cfg["output_len_bytes"])

    # CAUTION!!!!  ot.scope.clock.adc_freq must be read, due to side effects in its function..!!!!
    print(f'Scope setup with sampling rate {ot.scope.clock.adc_freq} S/s')
    # Ping target
    print('Reading from FPGA using simpleserial protocol.')
    version = None
    ping_cnt = 0
    while not version:
        if ping_cnt == 3:
            raise RuntimeError(
                f'No response from the target (attempts: {ping_cnt}).')
        ot.target.write('v' + '\n')
        ping_cnt += 1
        time.sleep(0.5)
        version = ot.target.read().strip()
    print(f'Target simpleserial version: {version} (attempts: {ping_cnt}).')
    return ot


@app.command()
def init(ctx: typer.Context):
    """Initalize target for SIFA."""
    initialize_capture(ctx.obj.cfg["device"], ctx.obj.cfg["capture"])


def capture_init(ctx, num_traces):
    """Initializes the user data stored in the context and programs the target."""
    cfg = ctx.obj.cfg
    if num_traces:
        cfg["capture"]["num_traces"] = num_traces


    # Key and plaintext generator
    ctx.obj.ktp = cw.ktp.Basic()
    ctx.obj.ktp.key_len = cfg["capture"]["key_len_bytes"]
    ctx.obj.ktp.text_len = cfg["capture"]["plain_text_len_bytes"]

    ctx.obj.ot = initialize_capture(cfg["device"], cfg["capture"])


def capture_loop(trace_gen, capture_cfg):
    """Main capture loop.

    Args:
      trace_gen: A trace generator.
      capture_cfg: Capture configuration.
    """
    project = cw.create_project(capture_cfg["project_name"], overwrite=True)
    for _ in tqdm(range(capture_cfg["num_traces"]), desc='Capturing', ncols=80):
        project.traces.append(next(trace_gen))
    project.save()



def capture_aes(ot, ktp, faults):
    """A generator for capturing AES traces.

    Args:
      ot: Initialized OpenTitan target.
      ktp: Key and plaintext generator.
    """
    key, _ = ktp.next()
    tqdm.write(f'Using key: {binascii.b2a_hex(bytes(key))}')
    cipher = AES.new(bytes(key), AES.MODE_ECB)
    while True:
        _, text = ktp.next()
        ret = cw.capture_trace(ot.scope, ot.target, text, key, ack=False)
        if not ret:
            raise RuntimeError('Capture failed.')
        expected = binascii.b2a_hex(cipher.encrypt(bytes(text)))
        got = binascii.b2a_hex(ret.textout)

        state_rec = sifa.decrypt_stepwise(ret.textout, list(key),(9, 'inv_shiftrows'))
        state_calc = sifa.encrypt_stepwise(list(text), list(key),(9, 'subbytes'), fault=False)
        state_diff= np.array(state_rec) ^ np.array(state_calc)
        if got != expected:
            faults[0] += 1
        else:
            faults[1] += 1
            yield ret


@app_capture.command()
def aes(ctx: typer.Context,
        num_traces: int = opt_num_traces):
    """Capture AES traces from a target that runs the `aes_serial` program."""
    capture_init(ctx, num_traces)
    faults = [0,0]
    capture_loop(capture_aes(ctx.obj.ot, ctx.obj.ktp, faults), ctx.obj.cfg["capture"])
    print("eff faults:  ", faults[0])
    print("ineff faults:", faults[1])
    print("ineff rate:  ", faults[1]/(faults[0]+faults[1])) 



@app.callback()
def main(ctx: typer.Context, cfg_file: str = None):
    """Capture traces for side-channel analysis."""

    cfg_file = 'capture_aes.yaml' if cfg_file is None else cfg_file
    with open(cfg_file) as f:
        cfg = yaml.load(f, Loader=yaml.FullLoader)

    # Store config in the user data attribute (`obj`) of the context.
    ctx.obj = SimpleNamespace(cfg=cfg)


if __name__ == "__main__":
    app()
