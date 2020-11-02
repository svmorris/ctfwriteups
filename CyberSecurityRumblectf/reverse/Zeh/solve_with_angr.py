import angr
import claripy
import subprocess
import sys

program_name      = "a.out"
find_address 	  = 0x00001253
num_bytes_of_flag = 0x04

import logging
logging.getLogger('angr').setLevel(logging.INFO)

# num_keys = get_arg()

proj = angr.Project(program_name,
                    main_opts = {"base_addr": 0}, # PIE binary
)

# create an array of bitvectors so that the value of each can easily be
# constrained to the range of printable ASCII characters
key_bytes = [claripy.BVS("byte_%d" % i, 8) for i in range(num_bytes_of_flag*8)]
key_bytes_AST = claripy.Concat(*key_bytes)

# we want to generate valid keys, so a symbolic variable is passed to 
# the state rather than a concrete value
state = proj.factory.full_init_state(args = ["./"+program_name], add_options=angr.options.unicorn)

# impose constraints on bitvectors the symbolic key is composed of
for byte in key_bytes:
    state.solver.add(byte >= 0x21, byte <= 0x7e)

sm = proj.factory.simulation_manager(state)

# find path to message indicating key was correct
sm.explore(find = find_address)

if len(sm.found) > 0:
    print("[ + ]  %s" % (sm.found[0].posix.dumps(0)))
else:
    print("[ x ] No solution found")