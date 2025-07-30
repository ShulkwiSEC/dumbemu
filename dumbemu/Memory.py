from unicorn import Uc, UcError
from .const import UC_PROT_ALL, STRING_CHUNK, MAX_STRING_LEN
from typing import Tuple
import struct

class Memory:
    """Memory management for emulation"""
    
    def __init__(self, uc: Uc) -> None:
        """Initialize with Unicorn engine instance"""
        self.uc = uc
        
    def map(self, addr: int, size: int, perm: int = UC_PROT_ALL) -> None:
        """Map memory region with permissions"""
        try:
            self.uc.mem_map(addr, size, perm)
        except UcError as e:
            raise RuntimeError(f"Memory mapping failed at 0x{addr:x}: {e}")
            
    def unmap(self, addr: int, size: int) -> None:
        """Unmap memory region"""
        try:
            self.uc.mem_unmap(addr, size)
        except UcError as e:
            raise RuntimeError(f"Memory unmapping failed at 0x{addr:x}: {e}")
            
    def write(self, addr: int, data: bytes) -> None:
        """Write data to memory"""
        try:
            self.uc.mem_write(addr, data)
        except UcError as e:
            raise ValueError(f"Memory write failed at 0x{addr:08x}: {e}")
            
    def read(self, addr: int, size: int) -> bytes:
        """Read data from memory"""
        try:
            return self.uc.mem_read(addr, size)
        except UcError as e:
            raise ValueError(f"Memory read failed at 0x{addr:08x}: {e}")
            
    def struct(self, addr: int, fmt: str) -> Tuple:
        """Read and unpack structure from memory"""
        size = struct.calcsize(fmt)
        data = self.read(addr, size)
        return struct.unpack(fmt, data)
        
    def pack(self, addr: int, fmt: str, *values) -> None:
        """Pack and write structure to memory"""
        data = struct.pack(fmt, *values)
        self.write(addr, data)
        
    def string(self, addr: int, wide: bool = False, max_len: int = MAX_STRING_LEN) -> str:
        """Read null-terminated string from memory"""
        data = bytearray()
        size = 2 if wide else 1
        
        for offset in range(0, max_len, STRING_CHUNK):
            try:
                chunk = self.read(addr + offset * size, STRING_CHUNK * size)
            except ValueError:
                break

            null = chunk.find(b'\x00\x00' if wide else b'\x00')
            if null != -1:
                data.extend(chunk[:null])
                break
            data.extend(chunk)

        return data.decode('utf-16-le' if wide else 'utf-8', errors='replace')
