from unicorn import Uc
from .const import (
    # Unicorn registers
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RSP, UC_X86_REG_RBP,
    UC_X86_REG_RIP, UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10,
    UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14,
    UC_X86_REG_R15, UC_X86_REG_EFLAGS, UC_X86_REG_EAX, UC_X86_REG_EBX,
    UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESI, UC_X86_REG_EDI,
    UC_X86_REG_ESP, UC_X86_REG_EBP, UC_X86_REG_EIP, UC_X86_REG_FS,
    UC_X86_REG_CS, UC_X86_REG_SS, UC_PROT_READ, UC_PROT_WRITE,
    # Memory and segment constants
    TIB_ADDR, PAGE_SIZE, GS_MSR, CS_X64, CS_X86, 
    SS_X64, SS_X86, FS_X86, STACK_X64, STACK_X86, STACK_SIZE
)
from typing import Tuple
from .Memory import Memory

class CPU:
    """CPU state and register management"""
    
    _REG_MAP = {
        'rax': UC_X86_REG_RAX, 'rbx': UC_X86_REG_RBX, 'rcx': UC_X86_REG_RCX, 
        'rdx': UC_X86_REG_RDX, 'rsi': UC_X86_REG_RSI, 'rdi': UC_X86_REG_RDI,
        'rsp': UC_X86_REG_RSP, 'rbp': UC_X86_REG_RBP, 'rip': UC_X86_REG_RIP, 
        'r8': UC_X86_REG_R8, 'r9': UC_X86_REG_R9, 'r10': UC_X86_REG_R10,
        'r11': UC_X86_REG_R11, 'r12': UC_X86_REG_R12, 'r13': UC_X86_REG_R13, 
        'r14': UC_X86_REG_R14, 'r15': UC_X86_REG_R15, 'eflags': UC_X86_REG_EFLAGS,
        'eax': UC_X86_REG_EAX, 'ebx': UC_X86_REG_EBX, 'ecx': UC_X86_REG_ECX, 
        'edx': UC_X86_REG_EDX, 'esi': UC_X86_REG_ESI, 'edi': UC_X86_REG_EDI,
        'esp': UC_X86_REG_ESP, 'ebp': UC_X86_REG_EBP, 'eip': UC_X86_REG_EIP
    }
    
    X64_ARG_REGS = [UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8, UC_X86_REG_R9]
    
    def __init__(self, uc: Uc, is_64bit: bool) -> None:
        """Initialize with Unicorn engine instance and architecture mode"""
        self.uc = uc
        self.is_64bit = is_64bit
        
    def read(self, reg_name: str) -> int:
        """Read register value"""
        try:
            return self.uc.reg_read(self._REG_MAP[reg_name.lower()])
        except KeyError:
            raise ValueError(f"Unknown register: {reg_name}")
            
    def write(self, reg_name: str, value: int) -> None:
        """Write register value"""
        try:
            self.uc.reg_write(self._REG_MAP[reg_name.lower()], value)
        except KeyError:
            raise ValueError(f"Unknown register: {reg_name}")

    def segments(self, mem: Memory) -> None:
        """Initialize segment registers"""    
        if self.is_64bit:
            mem.map(TIB_ADDR, PAGE_SIZE)
            self.uc.msr_write(GS_MSR, TIB_ADDR)
        else:
            self.uc.reg_write(UC_X86_REG_FS, FS_X86)

        self.uc.reg_write(UC_X86_REG_CS, CS_X64 if self.is_64bit else CS_X86)
        self.uc.reg_write(UC_X86_REG_SS, SS_X64 if self.is_64bit else SS_X86)
        
    def stack(self, mem: Memory) -> int:
        """Initialize stack memory and return stack pointer"""
        stack_addr = STACK_X64 if self.is_64bit else STACK_X86
        mem.map(stack_addr, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        sp = stack_addr + STACK_SIZE - 0x20
        self.uc.reg_write(UC_X86_REG_RSP if self.is_64bit else UC_X86_REG_ESP, sp)
        return sp
        
    def x64call(self, mem: Memory, sp: int, args: Tuple) -> int:
        """Setup x64 calling convention"""
        for i, arg in enumerate(args[:4]):
            self.uc.reg_write(self.X64_ARG_REGS[i], arg)
        
        # Shadow space and stack alignment
        sp -= 32
        for arg in reversed(args[4:]):
            sp -= 8
            mem.pack(sp, "<Q", arg)
        sp = sp & ~0xF  # 16-byte alignment
        self.uc.reg_write(UC_X86_REG_RSP, sp)
        return sp
        
    def x86call(self, mem: Memory, sp: int, args: Tuple) -> int:
        """Setup x86 calling convention"""
        for arg in reversed(args):
            sp -= 4
            mem.pack(sp, "<I", arg)
        self.uc.reg_write(UC_X86_REG_ESP, sp)
        return sp