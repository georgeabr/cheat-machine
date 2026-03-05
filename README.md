# Cheat Machine

A high-performance memory scanner and editor for Linux systems, written in C++17. This tool provides a professional ncurses interface for searching, narrowing, and freezing memory values in running processes.


You can use this tool to find and modify memory addresses responsible for game resources like gold, currency, health, and item counts.  

## Features

- Multi-threaded Scanning: Distributes workload across CPU cores using byte-based balancing for maximum efficiency.
- Optimised I/O: Uses the process_vm_readv system call to batch memory operations, significantly reducing overhead compared to standard read calls.
- Ncurses Interface: Provides a flicker-free, double-buffered terminal UI that handles complex input and window resizing.
- Integer Focus: Designed for high-speed integer scanning with smart type detection for i8, i16, i32, and i64.
- Memory Freezing: Background thread enforces value locks every 50ms to prevent the target process from altering specific addresses.
- Cache Management: Maps are parsed once and cached to prevent redundant file I/O during the UI refresh cycle.

## Prerequisites

- Linux operating system
- GCC 7 or higher (C++17 support)
- Ncurses development libraries
- Root privileges (required for cross-process memory access)

## Compilation

To compile the program, use the following command:

```sh
g++ -O3 -std=c++17 -o cheatmachine cheatmachine.cpp -lncurses -lpthread
```

## Usage

Start the program with sudo:

```sh
sudo ./cheatmachine
```

### Process Selector Controls

- Up / Down: Navigate the process list
- PgUp / PgDn: Scroll through list
- Type characters: Filter list by Name, PID, or Command
- Enter: Attach to the selected process
- R: Refresh the process list
- Esc: Exit the program

### Cheat Screen Controls

- S: New Scan - Start a fresh search
- N: Narrow - Filter current results by a new value
- E: Edit - Change the value of the selected address
- F: Freeze - Lock the selected address to a value
- U: Thaw - Remove a freeze lock from an address
- T: Type - Cycle through data types (i8, i16, i32, i64, f32, f64)
- Tab: Switch focus between Results and Frozen panels
- A: Add - Manually add a hex address
- C: Clear - Wipe the current results list
- P: Back - Return to the process selector
- Q / Esc: Quit the application

## Technical Notes

The scanner identifies writable memory regions from /proc/[pid]/maps while ignoring system-specific regions like [vvar].  
It uses 16 MiB chunks for scanning to balance memory usage and throughput.  
For integer types, it performs exact bitwise matching for maximum reliability.
