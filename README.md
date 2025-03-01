# Rust-Roblox-Pattern-Scanner

1. Process Discovery & Module Base Address Retrieval
Objective: Locate the running Roblox client (robloxplayerbeta.exe) and retrieve its Process ID (PID) and base memory address.

Mechanism:

ToolHelp Snapshots: Uses Windows' CreateToolhelp32Snapshot to iterate over all running processes.

Process Filtering: Checks for robloxplayerbeta.exe by name.

Module Enumeration: For the target process, retrieves the base address of its main module (typically the executable itself) via K32EnumProcessModules.

2. Memory Region Scanning
Objective: Traverse the Roblox client's memory to identify accessible regions for pattern extraction.

Mechanism:

VirtualQueryEx: Queries memory regions to determine their state (committed, free), protection flags (readable, executable), and size.

Access Checks: Skips guarded or non-readable regions (e.g., PAGE_GUARD, PAGE_NOACCESS).

Memory Read: Uses ReadProcessMemory to dump the contents of valid regions into a buffer for analysis.

3. Heuristic-Based Pattern Extraction
Objective: Identify candidate byte patterns that may represent code (e.g., function prologues, common instructions).

Heuristic:

Trigger Byte: Scans for the byte 0x55 (x86 assembly opcode for PUSH EBP, a common function prologue).

Pattern Capture: When 0x55 is found, captures the next 16 bytes as a candidate pattern.

Customization: The heuristic and pattern length (16 bytes) can be adjusted to target different code structures.

4. Output & Reporting
Colored Terminal Output: Uses the colored crate for user-friendly status messages:

Success: Displays PID, base address, and extracted patterns in cyan/green.

Errors: Highlights failures (e.g., process not found) in red.

Pattern Format: Each pattern is printed as:

Copy
[Pattern] Address: 0xABCD1234 -> 55 48 8B EC 48 83 EC 20 ...
5. Safety & Resource Management
Handle Guards: Uses Rust's Drop trait to automatically close handles (snapshots, process handles) and prevent leaks.

Error Handling: Gracefully exits on critical errors (e.g., process not found, memory read failure).

Key Use Cases
Reverse Engineering: Identify code patterns for analysis or hooking.

Cheat Development: Locate functions (e.g., player position updates, rendering routines) for modification.

Anti-Cheat Research: Study Roblox's memory layout or detect suspicious patterns.

Technical Limitations
Simple Heuristic: Relies on 0x55 as a trigger; may generate false positives or miss patterns.

Fixed Pattern Length: Assumes 16-byte patterns; real-world signatures may vary.

No Cross-Platform Support: Relies on Windows APIs (not compatible with other OSes).

Performance Considerations
Memory Scan Speed: Scanning large regions (e.g., hundreds of MB) can take time. The code tracks and reports scan duration.

Optimization: Sliding window iteration (checking every byte) is computationally intensive but necessary for thoroughness.
