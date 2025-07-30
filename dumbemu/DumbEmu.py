# DumbEmu: emulator for PE executables using Unicorn Engine
from unicorn import Uc, UcError
from .const import (
    # Unicorn architecture and mode
    UC_ARCH_X86, UC_MODE_64, 
    # Hooks and memory access
    UC_HOOK_CODE, UC_HOOK_MEM_UNMAPPED, UC_HOOK_INTR,
    UC_MEM_WRITE_UNMAPPED, UC_MEM_READ_UNMAPPED,
    # Error codes
    UC_ERR_OK, UC_ERR_FETCH_UNMAPPED, 
    # Memory permissions
    UC_PROT_READ, UC_PROT_WRITE,
    # Memory constants
    PAGE_SIZE, STACK_SIZE, STACK_X64, STACK_X86,
    TIB_ADDR, FAKE_RET_ADDR, GS_MSR, CS_X64, CS_X86,
    SS_X64, SS_X86, FS_X86, STRING_CHUNK, MAX_STRING_LEN
)
from .PEFile import PEFile
from .Memory import Memory
from .CPU import CPU
from typing import Dict, Callable
import struct

class DumbEmu:
    """Simplified PE emulator for function execution without DLLs/syscalls"""
    
    def __init__(self, path: str, arch: int = UC_ARCH_X86, mode: int = UC_MODE_64) -> None:
        """Initialize emulator for PE file"""
        self.is_64bit = (mode == UC_MODE_64)
        self.hooks: Dict[int, Callable] = {}
        self.instr_count: int = 0
        self.last_addr: int = 0
        
        self.pe = PEFile(path)
        if self.pe.is_64bit != self.is_64bit:
            raise RuntimeError(f"Architecture mismatch: PE is {'' if self.pe.is_64bit else 'not '}64-bit")
        
        self.uc = Uc(arch, mode)
        self.mem = Memory(self.uc)
        self.cpu = CPU(self.uc, self.is_64bit)
        
        self.base = self.pe.base
        self.size = self.pe.size
        
        self._init()
        
    def _init(self) -> None:
        """Initialize emulation environment"""
        self.mem.map(self.base, self.size, UC_PROT_READ | UC_PROT_WRITE)

        for addr, data, perms in self.pe.sections():
            try:
                aligned_size = (len(data) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)
                self.mem.write(addr, data.ljust(aligned_size, b'\x00'))
                page_addr = addr & ~(PAGE_SIZE - 1)
                page_size = ((addr + len(data) + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)) - page_addr
                self.uc.mem_protect(page_addr, page_size, perms)
            except UcError:
                continue

        for addr, size, delta in self.pe.relocs(self.base):
            try:
                if size == 4:
                    val = struct.unpack("<I", self.mem.read(addr, 4))[0] + delta
                    self.mem.write(addr, struct.pack("<I", val))
                elif size == 8:
                    val = struct.unpack("<Q", self.mem.read(addr, 8))[0] + delta
                    self.mem.write(addr, struct.pack("<Q", val))
            except ValueError:
                continue

        self.cpu.stack(self.mem)
        self.cpu.segments(self.mem)
        
        self._hooks()
    
    def _hooks(self) -> None:
        """Initialize instruction hooks"""
        def hook_code(uc, addr, size, _):
            self.last_addr = addr
            self.instr_count += 1
            if addr in self.hooks:
                self.hooks[addr](self, addr)

        def hook_mem_invalid(uc, access, addr, size, _, __):
            if access in (UC_MEM_WRITE_UNMAPPED, UC_MEM_READ_UNMAPPED):
                page = addr & ~(PAGE_SIZE - 1)
                try:
                    self.mem.map(page, PAGE_SIZE, UC_PROT_READ | UC_PROT_WRITE)
                    return True
                except RuntimeError:
                    return False
            return False

        def hook_intr(uc, intno, _):
            if intno == 0x3:
                uc.emu_stop()

        self.uc.hook_add(UC_HOOK_CODE, hook_code)
        self.uc.hook_add(UC_HOOK_MEM_UNMAPPED, hook_mem_invalid)
        self.uc.hook_add(UC_HOOK_INTR, hook_intr)
        
    def hook(self, addr: int, callback: Callable) -> None:
        """Add execution hook at address"""
        self.hooks[addr] = callback
        
    def call(self, addr: int, breakpoint: int = None, *args) -> int:
        """Call function at address with arguments, optionally stopping at specified address
        
        Args:
            addr: Function address to call
            breakpoint: Optional address to stop execution at (default: None)
            *args: Function arguments
            
        Returns:
            Return value from function (RAX/EAX)
        """

        sp = self.cpu.read('rsp' if self.is_64bit else 'esp')
        
        if self.is_64bit:
            sp = self.cpu.x64call(self.mem, sp, args)
        else:
            sp = self.cpu.x86call(self.mem, sp, args)

        ret_val = [0]
        temp_hook = object()
        bp_hook = object() if breakpoint else None

        def ret_hook(emu, _):
            ret_val[0] = emu.cpu.read('rax' if emu.is_64bit else 'eax')
            emu.uc.emu_stop()
            
        if breakpoint:
            def break_hook(emu, _):
                ret_val[0] = emu.cpu.read('rax' if emu.is_64bit else 'eax')
                emu.uc.emu_stop()
            self.hooks[bp_hook] = break_hook
            self.hook(breakpoint, break_hook)

        self.hooks[temp_hook] = ret_hook
        self.mem.map(FAKE_RET_ADDR, PAGE_SIZE)
        self.mem.write(FAKE_RET_ADDR, b"\xCC" * PAGE_SIZE)

        try:
            self.uc.emu_start(addr, FAKE_RET_ADDR)
        except UcError as e:
            if e.errno not in (UC_ERR_OK, UC_ERR_FETCH_UNMAPPED):
                raise
        finally:
            del self.hooks[temp_hook]
            if bp_hook and bp_hook in self.hooks:
                del self.hooks[bp_hook]
            self.mem.unmap(FAKE_RET_ADDR, PAGE_SIZE)

        return ret_val[0]
        
    def read(self, addr: int, size: int) -> bytes:
        """Read from emulated memory"""
        return self.mem.read(addr, size)
        
    def write(self, addr: int, data: bytes) -> None:
        """Write to emulated memory"""
        self.mem.write(addr, data)
        
    def string(self, addr: int, wide: bool = False, max_len: int = MAX_STRING_LEN) -> str:
        """Read null-terminated string from memory"""
        return self.mem.string(addr, wide, max_len)