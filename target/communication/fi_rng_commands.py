# Copyright lowRISC contributors.
# Licensed under the Apache License, Version 2.0, see LICENSE for details.
# SPDX-License-Identifier: Apache-2.0
"""Communication interface for OpenTitan RNG FI framework.

Communication with OpenTitan happens over the uJSON command interface.
"""
import json
import time
from typing import Optional


class OTFIRng:
    def __init__(self, target) -> None:
        self.target = target

    def _ujson_rng_fi_cmd(self) -> None:
        time.sleep(0.01)
        self.target.write(json.dumps("RngFi").encode("ascii"))

    def init(self) -> None:
        """ Initialize the rng FI code on the chip.
        Args:
            cfg: Config dict containing the selected test.
        """
        # rngFi command.
        self._ujson_rng_fi_cmd()
        # InitTrigger command.
        time.sleep(0.01)
        self.target.write(json.dumps("Init").encode("ascii"))

    def start_test(self, cfg: dict) -> None:
        """ Start the selected test.

        Call the function selected in the config file. Uses the getattr()
        construct to call the function.

        Args:
            cfg: Config dict containing the selected test.
        """
        test_function = getattr(self, cfg["test"]["which_test"])
        test_function()

    def read_response(self, max_tries: Optional[int] = 1) -> str:
        """ Read response from rng FI framework.
        Args:
            max_tries: Maximum number of attempts to read from UART.

        Returns:
            The JSON response of OpenTitan.
        """
        it = 0
        while it != max_tries:
            read_line = str(self.target.readline())
            if "RESP_OK" in read_line:
                return read_line.split("RESP_OK:")[1].split(" CRC:")[0]
            it += 1
        return ""
