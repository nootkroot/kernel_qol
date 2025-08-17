from typing import Iterator, List, Mapping, Optional, Tuple, Union

from binaryninja import (BasicBlock, BinaryView, DisassemblyTextLine, Function,
                         InstructionTextToken, LinearDisassemblyLine,
                         LinearViewObject, MediumLevelILCall, RenderLayer,
                         RenderLayerDefaultEnableState)
from binaryninja.commonil import Call
from binaryninja.enums import InstructionTextTokenType, MediumLevelILOperation
from binaryninja.log import log_error, log_info, log_warn


class PrintkRenderLayer(RenderLayer):
    name = "Fix printk strings"
    default_enable_state = RenderLayerDefaultEnableState.EnabledByDefaultRenderLayerDefaultEnableState

    def get_printk_address(
        self,
        bv: BinaryView
    ) -> int:
        symbol = bv.get_symbol_by_raw_name("printk")
        if not symbol:
            symbol = bv.get_symbol_by_raw_name("_printk")
            if not symbol:
                return 0

        return symbol.address

    def get_log_level(
        self,
        log_level: str
    ) -> str:
        match log_level:
            case '0':
                return "KERN_EMERG"
            case '1':
                return "KERN_ALERT"
            case '2':
                return "KERN_CRIT"
            case '3':
                return "KERN_ERR"
            case '4':
                return "KERN_WARNING"
            case '5':
                return "KERN_NOTICE"
            case '6':
                return "KERN_INFO"
            case '7':
                return "KERN_DEBUG"
            case 'c':
                return "KERN_CONT"
            case _:
                return ""

    def apply_to_lines(
        self,
        block: BasicBlock | Function,
        lines: Union[List["DisassemblyTextLine"],
                     List["LinearDisassemblyLine"]]
    ) -> Union[List["DisassemblyTextLine"],
               List["LinearDisassemblyLine"]]:
        bv = block.view
        if not bv:
            log_error("BinaryView not found")
            return lines

        printk_address = self.get_printk_address(bv)
        if not printk_address:
            return lines

        for line in lines:
            if isinstance(line, LinearDisassemblyLine):
                line = line.contents
            il_instr = line.il_instruction
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
                header = bv.read(fmt_addr-2, 2)
                if header[0] != 1:
                    continue

            log_level = self.get_log_level(chr(header[1]))

            tokens = line.tokens
            idx = 0
            for i, token in enumerate(tokens):
                if token.text in ["printk", "_printk"]:
                    idx = i
                    break
            else:
                continue

            tokens.insert(
                idx+2, InstructionTextToken(InstructionTextTokenType.TextToken, log_level+" "))

        return lines

    def apply_to_medium_level_il_block(
        self,
        block: BasicBlock,
        lines: List["DisassemblyTextLine"]
    ) -> List["DisassemblyTextLine"]:
        return self.apply_to_lines(block, lines)

    def apply_to_high_level_il_block(
        self,
        block: BasicBlock,
        lines: List["DisassemblyTextLine"]
    ) -> List["DisassemblyTextLine"]:
        return self.apply_to_lines(block, lines)

    def apply_to_high_level_il_body(
        self,
        function: 'Function',
        lines: List['LinearDisassemblyLine']
    ) -> List['LinearDisassemblyLine']:
        return self.apply_to_lines(function, lines)

        return lines
