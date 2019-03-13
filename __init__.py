# https://www.cs.ucsb.edu/~yufeiding/cs293s/slides/293S_07_SSA_dead.pdf (for worklist style algorithm)


import sys

from binaryninja.log import log_info
from binaryninja.binaryview import BinaryViewType
from binaryninja.plugin import PluginCommand
from binaryninja.plugin import BackgroundTaskThread
from binaryninja.enums import (MediumLevelILOperation, RegisterValueType)


def is_critical(instruction):
    bb = instruction.il_basic_block
    if len(bb.outgoing_edges) > 1:
        for outgoing in bb.outgoing_edges:
            if len(outgoing.target.incoming_edges) > 1:
                return True
    return False


def mark(bv, status, function):
    bv.update_analysis_and_wait()
    marks = {}
    worklist = []
    for bb in function.mlil:
        for instruction in bb:
            # allow UI to cancel the analysis
            if status.cancelled:
                break

            ssa_var = instruction.ssa_form
            for written in instruction.vars_written:
                marks[written] = False

            if is_critical(instruction):
                for written in instruction.vars_written:
                    marks[written] = True
                if instruction not in worklist:  # unnecessary?
                    worklist.append(ssa_var)

    while len(worklist) > 0:
        instruction = worklist.pop()
        for op in instruction.vars_read:
            if op in marks:
                if not marks[op]:
                    for definition in function.medium_level_il.get_ssa_var_definition(op):
                        marks[definition] = True
                        worklist.append(definition)

    return marks


def sweep(function, marks):
    for bb in function.mlil:
        for instruction in bb:
            for written in instruction.vars_written:
                if not marks[written]:
                    if instruction.instr_index == bb.end:  # if instruction is a jump/if
                        print("updating branch at {}...", instruction.address)
                    else:
                        print("eliminating instruction at {}...", instruction.address)


def eliminate_dead_code(bv, status, function):
    analysis_pass = 0
    while True:
        print("starting analysis pass {}...", analysis_pass)
        analysis_pass += 1
        marks = mark(bv, status, function)
        sweep(function, marks)


class DeadCodeEliminator(BackgroundTaskThread):
    def __init__(self, bv, msg):
        BackgroundTaskThread.__init__(self, msg, True)
        self.bv = bv

    def __init__(self, bv, msg, function_name):
        BackgroundTaskThread.__init__(self, msg, True)
        self.bv = bv
        self.function = function_name

    def run(self):
        eliminate_dead_code(self.bv, self, self.function)


def run_in_background(bv, function):
    background_task = DeadCodeEliminator(bv, "Patching dead code...", function)
    background_task.start()


def main():
    bv = BinaryViewType.get_view_of_file(sys.argv[1])
    if bv is None:
        print("Couldn't open " + sys.argv[1])
        return

    eliminate_dead_code(bv)

    dbname = sys.argv[1]
    if not dbname.endswith(".bndb"):
        dbname += ".bndb"

    bv.create_database(dbname)


if __name__ == "__main__":
    main()
else:
    PluginCommand.register_for_function(
        "Eliminate Dead Code",
        "Patch out dead code in the current function",
        run_in_background)
