from binaryninja import (
    StringRecognizer,
    CustomStringType,
    DataBuffer,
    DerivedString,
    DerivedStringLocation,
    DerivedStringLocationType,
    IntegerType,
    InstructionTextToken,
    InstructionTextTokenType,
    HighLevelILFunction,
    HighLevelILInstruction,
    Type,
    Call,
    BinaryView,
)


class PrintkStringRecognizer(StringRecognizer):
    recognizer_name = "printk_strings"

    def get_printk_address(self, bv: BinaryView) -> int:
        symbol = bv.get_symbol_by_raw_name("printk")
        if not symbol:
            symbol = bv.get_symbol_by_raw_name("_printk")
            if not symbol:
                return 0

        return symbol.address

    def get_log_level(self, log_level: str) -> str:
        match log_level:
            case "0":
                return "KERN_EMERG"
            case "1":
                return "KERN_ALERT"
            case "2":
                return "KERN_CRIT"
            case "3":
                return "KERN_ERR"
            case "4":
                return "KERN_WARNING"
            case "5":
                return "KERN_NOTICE"
            case "6":
                return "KERN_INFO"
            case "7":
                return "KERN_DEBUG"
            case "c":
                return "KERN_CONT"
            case _:
                return ""

    def get_string(self, bv: BinaryView, addr: int) -> bytes:
        i = 0
        result = b""
        while True:
            byte = bv.read(addr + i, 1)
            if len(byte) != 1:
                return b""
            if byte[0] == 0:
                break
            result += byte
            i += 1

        return result

    def is_valid_for_type(self, func: HighLevelILFunction, type: Type) -> bool:
        if not isinstance(type, IntegerType):
            return False

        return True

    def recognize_constant(
        self, instr: HighLevelILInstruction, _type: Type, val: int
    ) -> DerivedString | None:
        func = instr.function
        call = func.get_expr(instr.core_instr.parent)
        if not isinstance(call, Call):
            return None

        bv = func.view
        printk_address = self.get_printk_address(bv)
        if not printk_address:
            return None

        if call.dest.value != printk_address:
            return None

        header = bv.read(val, 2)

        if header[0] != 1:
            return None

        prefix = self.get_log_level(chr(header[1]))

        printk_string_type = CustomStringType.register(
            "printk_string", prefix + " ", ""
        )

        string_addr = val + 2
        printk_string = self.get_string(bv, string_addr)

        loc = DerivedStringLocation(
            DerivedStringLocationType.DataBackedStringLocation,
            string_addr,
            len(printk_string),
        )
        return DerivedString(printk_string, loc, printk_string_type)
