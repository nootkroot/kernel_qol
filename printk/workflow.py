from typing import Iterator, List, Mapping, Tuple

from binaryninja import (Activity, AnalysisContext, BasicBlock, BinaryView,
                         DisassemblyTextLine, Function, InstructionTextToken,
                         LinearDisassemblyLine, MediumLevelILCall,
                         MediumLevelILConstPtr, RenderLayer,
                         RenderLayerDefaultEnableState, Workflow)
from binaryninja.commonil import Call
from binaryninja.enums import InstructionTextTokenType, MediumLevelILOperation
from binaryninja.log import log_debug, log_error, log_info, log_warn


def get_printk_address(
    bv: BinaryView
) -> int:
    symbol = bv.get_symbol_by_raw_name("printk")
    if not symbol:
        symbol = bv.get_symbol_by_raw_name("_printk")
        if not symbol:
            return 0

    return symbol.address


def fix_printk_strings(analysis_context: AnalysisContext):
    update = False
    function = analysis_context.mlil
    bv = function.view
    if not bv:
        log_error("BinaryView not found")
        return

    printk_address = get_printk_address(bv)
    if not printk_address:
        return

    for il_instr in function.instructions:
        if not isinstance(il_instr, Call):
            continue

        if il_instr.dest.value != printk_address:
            continue

        args = il_instr.operands[-1]
        if not args:
            log_error("No arguments in printk")
            continue

        fmt = args[0]
        fmt_addr = fmt.value.value
        header = bv.read(fmt_addr, 2)
        if header[0] != 1:
            continue

        function.replace_expr(
            fmt, function.const_pointer(fmt.size-2, fmt_addr+2))

        update = True

    if update:
        function.generate_ssa_form()


PrintkWorkflow = Workflow("core.function.metaAnalysis").clone(
    "core.function.metaAnalysis")
PrintkWorkflow.register_activity(
    Activity("analysis.plugin.fixPrintkStrings", action=fix_printk_strings))
PrintkWorkflow.insert(
    "core.function.generateHighLevelIL", ["analysis.plugin.fixPrintkStrings"])
