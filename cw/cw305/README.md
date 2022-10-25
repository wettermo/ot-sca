### SIFA (Statistical Ineffective Fault Attack) on OpenTitan AES

How to perform SIFA on AES in Verilator Simulation:

1. **Generate plaintexts:**

   - `$python sifa_gen_aes_plaintexts.py -k 0x11223344556677889900aabbccddeeff -s 128 -n 1000`

   - `-k`: key, `-s`: key size, `-n`: number of plaintexts (for further information use `$python sifa_gen_aes_plainytexts.py -h`)

   - This python script generates a `.csv` file containing plaintext key pairs together with the expected ciphertext.
   - Note that the required byte order for plaintext, key and ciphertext is little endian

2. **Simulate faulty (synthesized) AES design using Verilator:**

   - This has to be done inside the "opentitan" repository : `$cd /path/to/opentitan`
   - If necessary edit the file path for the output `.csv` file inside `opentitan/hw/ip/aes/pre_dv/aes_wrap_tb/rtl/aes_wrap_tb.sv` (for synthesized AES simulation: `opentitan/hw/ip/aes/pre_dv/aes_syn_wrap_tb/rtl/aes_syn_wrap_tb.sv`) so that the output file is created inside this `./` directory
   - Build the Verilator simulation: `$fusesoc --cores-root=. run --setup --build lowrisc:dv_verilator:aes_wrap_tb` (for synthesized AES simulation: `$fusesoc --cores-root=. run --setup --build lowrisc:dv_verilator:aes_syn_wrap_tb`)
   - Execute the simulation: `$./build/lowrisc_dv_verilator_aes_wrap_tb_0/default-verilator/Vaes_wrap_tb --trace` (for synthesized AES simulation: `$./build/lowrisc_dv_verilator_aes_syn_wrap_tb_0/default-verilator/Vaes_syn_wrap_tb --trace`)
   - The simulation generates a `.csv` file containing plaintext, ciphertext, key and expected ciphertext without fault injection.

3. **Perform SIFA attack:**

   - If necessary edit the file path for the output `.csv` file inside `./simple_sifa_attack.py`

   - `$python simple_sifa_attack.py -a verilator ` or `$python simple_sifa_attack.py -a -s verilator ` for synthesized simulation (further information: `$python simple_sifa_attack.py -h`)

     
     