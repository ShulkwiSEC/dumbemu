# DumbEmu
A lightweight, minimal-dependency PE file emulator built on top of Unicorn Engine. DumbEmu calls functions from PE (Portable Executable) files and supports both 32-bit and 64-bit Windows executables.

## Features

- **Architecture Support:** Both x86 (32-bit) and x64 (64-bit) PE files  
- **PE Loading:** Automatic section mapping with proper permissions  
- **Relocation Handling:** Applies base relocations for position-independent code  
- **Memory Management:**  
  - Automatic handling of unmapped memory access (lazy allocation)  
  - Memory protection and permissions  
  - Utilities for reading/writing structures and strings  
- **CPU State Management:**  
  - Register access for all x86/x64 registers  
  - Proper segment initialization (CS, SS, GS, FS)  
  - TIB (Thread Information Block) setup  
- **Function Calling:**  
  - Proper implementation of x86 and x64 calling conventions  
  - Support for variable number of arguments  
  - Return value capturing  
  - Optional breakpoint for stopping execution  
- **Execution Hooks:**  
  - Address-specific execution hooks  
  - Interrupt handlers  
- **String Utilities:**  
  - Reading null-terminated ASCII and wide strings.

## Limitations

- No system API emulation (no Windows API functions)
- No DLL loading or handling of imports
- Limited to function-level execution
- No thread support
- No exception handling
- Memory access outside mapped regions will be silently allocated

## Getting Started

### Requirements

- Python 3.6+
- unicorn-engine
- pefile

Install the required dependencies using pip:

```bash
pip install dumbemu
```

## Dirct from GIT
```bash
pip install git+https://github.com/Diefunction/dumbemu.git
```

## OR Manule
```bash
git clone https://github.com/Diefunction/dumbemu
pip install unicorn
pip install pefile
```

## Usage Examples

### Basic Example - Calling a Function

```python
from dumbemu import DumbEmu

# Load and initialize a PE file (arch is auto-detected)
emu = DumbEmu("binary.exe")

# Call a function at address 0x401000 with arguments
result = emu.call(0x401000, None, 1, 2, 3, "hello".encode())
print(f"Function returned: {result}")

# Read memory and extract results
data = emu.read(0x401500, 16)
print(f"Memory at 0x401500: {data.hex()}")

# Read a null-terminated string
string = emu.string(0x402000)
print(f"String at 0x402000: {string}")
```

### Example with Memory Allocation and Register Setup

```python
from dumbemu import DumbEmu
from unicorn.x86_const import UC_MODE_64

# Initialize emulator
emu = DumbEmu("binary.exe", mode=UC_MODE_64)

# Allocate memory for our buffer
buf = 0x200000
emu.mem.map(buf, 0x1000)

# Set up input and registers
rbp = buf + 0x100
emu.cpu.write('rbp', rbp)
print(f"Set RBP to 0x{rbp:X}")

INPUT_OFFSET = rbp - 0x39

# Write to the input buffer
emu.write(INPUT_OFFSET, 'HelloWorld'.encode())

# Define the function address to call
addr = 0x401000  # Replace with actual function address
breakpoint = 0x401100  # Or a specific address to stop at (breakpoint)

# Call the function
emu.call(addr, breakpoint)

# Check return value
if emu.cpu.read('eax') == 1:
    print('[+] Success')
```

### Example with Execution Monitoring

```python
from dumbemu import DumbEmu

emu = DumbEmu("binary.exe")

# Define a monitoring hook function
# This will be called whenever execution reaches the target address
def monitor(emu, address):
    # Print current state
    print(f"[*] Execution reached 0x{address:X}")
    rax = emu.cpu.read('rax')
    rbx = emu.cpu.read('rbx')
    rcx = emu.cpu.read('rcx')
    
    print(f"[*] RAX = 0x{rax:X}, RBX = 0x{rbx:X}, RCX = 0x{rcx:X}")
    
    # Optionally modify state
    if rax == 0x1234:
        print("[+] Found target value in RAX!")
        emu.cpu.write('rdx', 0xDEADBEEF)  # Modify another register
    
    # You can access memory too
    try:
        # Read 16 bytes from address pointed to by RCX
        data = emu.read(rcx, 16)
        print(f"[*] Data at RCX: {data.hex()}")
    except:
        print("[!] Unable to read from RCX")

# Add hooks at multiple addresses
emu.hook(0x401000, monitor)  # Monitor function entry
emu.hook(0x401123, monitor)  # Monitor specific instruction
emu.hook(0x401500, monitor)  # Monitor potential exit point

# Prepare arguments
args = (0x12345678, 0xAABBCCDD)

# Call the function with monitoring enabled
result = emu.call(0x401000, None, *args)

print(f"[*] Function returned: 0x{result:X}")
```

## API Reference

### DumbEmu

```python
DumbEmu(path: str, arch: int = UC_ARCH_X86, mode: int = UC_MODE_64)
```

- `path`: PE file path
- `arch`: Unicorn architecture (default: UC_ARCH_X86)
- `mode`: Unicorn mode (default: UC_MODE_64)

#### Methods

- `call(addr: int, breakpoint: int = None, *args) -> int`: Call function at address with arguments
- `hook(addr: int, callback: Callable) -> None`: Add execution hook at address
- `read(addr: int, size: int) -> bytes`: Read from emulated memory
- `write(addr: int, data: bytes) -> None`: Write to emulated memory
- `string(addr: int, wide: bool = False, max_len: int = MAX_STRING_LEN) -> str`: Read null-terminated string from memory

___
# Contrubie
__
### Codebase:
```
dumbemu/
│
├── dumbemu/          ← this should be a folder (package) containing your code
│   ├── __init__.py
│   ├── DumbEmu.py
│   ├── CPU.py
│   ├── Memory.py
│   ├── PEFile.py
│   ├── const.py
│
├── setup.py
├── README.md
└── .gitignore
```