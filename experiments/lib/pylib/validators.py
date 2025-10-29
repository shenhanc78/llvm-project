from collections import defaultdict

class Validator:
    # Help with verifying parsing output correctness
    def __init__(self, system_arch: str, abi: str):
        if system_arch == "x86-64":
            if abi == "System V":
                self.callee_register_set = {"$rbx", "$rbp", "$r12", "$r13", "$r14", "$r15"}
                self.callee_register_num = 6
            else:
                raise NotImplementedError(f"System Arch={system_arch}|ABI={abi} has no implementation.")
        else:
            raise NotImplementedError(f"System Arch={system_arch}|ABI={abi} has no implementation.")

    def validate_regs(self, reg_list, line):
        if len(reg_list) > self.callee_register_num:
            raise ValueError(f"Somehow register list length > 6.\n\tregs_list: {reg_list}.\n\tLine: {line}.")
        for reg in reg_list:
            if reg not in self.callee_register_set:
                raise ValueError(f"{reg} is not a callee-saved register.\nLine:{line}.")