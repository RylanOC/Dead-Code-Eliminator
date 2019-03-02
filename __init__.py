from binaryninja import *

# https://www.cs.ucsb.edu/~yufeiding/cs293s/slides/293S_07_SSA_dead.pdf (for worklist style algorithm)

# driver function
def find_dead_code(bv,function):


# check if a basic block contains critical edges
# (edges from a basic block with multiple successors to one with multiple predecessors)
def is_critical(bb):


# worklist style function to recursively find all dead code
def mark(bv):


# delete redundant code (or modify destinations in the case of jumps)
def sweep(bv, marks):



PluginCommand.register_for_address("Dead Code Eliminator", "Detects and eliminates dead code in the current binary", find_dead_code())
