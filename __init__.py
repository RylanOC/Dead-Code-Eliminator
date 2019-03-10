# https://www.cs.ucsb.edu/~yufeiding/cs293s/slides/293S_07_SSA_dead.pdf (for worklist style algorithm)


import sys

from binaryninja.log import log_info
from binaryninja.binaryview import BinaryViewType
from binaryninja.plugin import PluginCommand
from binaryninja.plugin import BackgroundTaskThread
from binaryninja.enums import (MediumLevelILOperation, RegisterValueType)


def is_static(i):
    return True


def mark(bv, marks, status, function):
    bv.update_analysis_and_wait()

    worklist = []
    for bb in function.mlil:
        for instruction in bb:
            # allow UI to cancel the analysis
            if status.cancelled:
                break

            ssa_var = instruction.ssa_form
            for written in instruction.vars_written:
                marks[written] = False

            if is_static(instruction):
                for written in instruction.vars_written:
                    marks[written] = True
                if instruction not in worklist:  # unnecessary?
                    worklist.append(ssa_var)

    while len(worklist) > 0:
        instruction = worklist.pop()
        for op in instruction.vars_read:
            if not marks[op]:
                for definition in function.medium_level_il.get_ssa_var_definition(op):
                    marks[definition] = True
                    worklist.append(definition)





    '''
    patch_locations = []
    for i in bv.mlil_instructions:
        # Allow the UI to cancel the action
        if status.cancelled:
            break

        if i.operation != MediumLevelILOperation.MLIL_IF:
            continue
        # Get the possible_values of the condition result
        condition_value = i.condition.possible_values
        # If the condition never changes then its safe to patch the branch
        if condition_value.type == RegisterValueType.ConstantValue:
            if condition_value.value == 0 and bv.is_never_branch_patch_available(i.address):
                patch_locations.append((i.address, True))
            elif bv.is_always_branch_patch_available(i.address):
                patch_locations.append((i.address, False))

    return patch_locations
    '''


def eliminate_dead_code(bv, status):
    analysis_pass = 0
    while True:
        analysis_pass += 1
        patch_locations = mark(bv, status)
        if len(patch_locations) == 0 or analysis_pass == 10 or status.cancelled:
            break
        for address, always in patch_locations:
            if always:
                log_info("Patching instruction {} to never branch.".format(hex(address)))
                bv.never_branch(address)
            else:
                log_info("Patching instruction {} to always branch.".format(hex(address)))
                bv.always_branch(address)


class DeadCodeEliminator(BackgroundTaskThread):
    def __init__(self, bv, msg):
        BackgroundTaskThread.__init__(self, msg, True)
        self.bv = bv

    def run(self):
        eliminate_dead_code(self.bv, self)


def run_in_background(bv):
    background_task = DeadCodeEliminator(bv, "Patching dead code...")
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
    PluginCommand.register("Eliminate Dead Code", "Patch out all useless code in the binary", run_in_background)
