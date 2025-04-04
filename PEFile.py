import pefile
from typing import List, Tuple
from .const import PAGE_SIZE, UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC
from unicorn import UcError

class PEFile:
    """Handler for PE file loading and processing"""
    
    def __init__(self, path: str) -> None:
        """Initialize with PE file path"""
        try:
            self.pe = pefile.PE(path)
        except pefile.PEFormatError as e:
            raise RuntimeError(f"Invalid PE file: {e}")
            
        self.path = path
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.size = self._align(self.pe.OPTIONAL_HEADER.SizeOfImage)
        self.is_64bit = self._check()
        
    def _check(self) -> bool:
        """Check if PE is 64-bit or 32-bit"""
        machine = self.pe.FILE_HEADER.Machine
        return machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']
        
    def _align(self, val: int, align: int = PAGE_SIZE) -> int:
        """Align memory address to boundary"""
        return (val + align - 1) & ~(align - 1)
        
    def sections(self) -> List[Tuple[int, bytes, int]]:
        """Get list of (address, data, permissions) for each section"""
        result = []
        for section in self.pe.sections:
            addr = self.base + section.VirtualAddress
            data = section.get_data()
            perms = UC_PROT_READ | (UC_PROT_EXEC if section.Characteristics & 0x20000000 else UC_PROT_WRITE)
            result.append((addr, data, perms))
        return result
        
    def relocs(self, new_base: int) -> List[Tuple[int, int, int]]:
        """Get relocations as (address, size, value_delta)"""
        if not hasattr(self.pe, 'DIRECTORY_ENTRY_BASERELOC'):
            return []
        
        delta = new_base - self.pe.OPTIONAL_HEADER.ImageBase
        if delta == 0:
            return []
            
        result = []
        for block in self.pe.DIRECTORY_ENTRY_BASERELOC:
            for entry in block.entries:
                if entry.type not in (
                    pefile.RELOCATION_TYPE['IMAGE_REL_BASED_HIGHLOW'],
                    pefile.RELOCATION_TYPE['IMAGE_REL_BASED_DIR64']
                ):
                    continue
                    
                addr = new_base + block.struct.VirtualAddress + entry.rva
                size = 8 if entry.type == pefile.RELOCATION_TYPE['IMAGE_REL_BASED_DIR64'] else 4
                result.append((addr, size, delta))
                
        return result
