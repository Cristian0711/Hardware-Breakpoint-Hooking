# HWBP - Hardware Breakpoint Library

![C++](https://img.shields.io/badge/C++-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![Debug](https://img.shields.io/badge/Debug-5C2D91?style=for-the-badge&logoColor=white)

A lightweight, thread-safe C++ library for managing hardware breakpoints on x86/x64 Windows systems. This implementation provides a clean interface for setting up execution breakpoints with custom callbacks, with a focus on security and stealth.

## 🔍 Features

- **Hardware-based breakpoints**: Utilizes CPU debug registers (DR0-DR3) to set execution breakpoints
- **Thread-specific hooking**: Target specific threads or the current thread
- **Custom exception handling**: Execute custom code when breakpoints are triggered
- **Automatic repatch mechanism**: Enables breakpoints after execution to maintain hook persistence
- **Garbage collection**: Optional cleanup of hooks to prevent detection
- **Anti-detection measures**: Designed to be difficult to detect by anti-cheat systems

## 🚀 Usage

### Basic Example

```cpp
#include "hwbp.h"

void main() {
    // Initialize the HWBP system
    hwbp::get().setup();
    
    // Hook the current thread at a specific address
    hwbp::get().hook_current_thread(
        0x12345678,                              // Address to hook
        [](PEXCEPTION_POINTERS exception_info) { // Callback
            // Custom code to execute when the breakpoint is hit
            std::cout << "Breakpoint triggered!" << std::endl;
            
            // Access registers via exception_info->ContextRecord
            auto eax = exception_info->ContextRecord->Eax;
            exception_info->ContextRecord->Eax = 0; // Modify registers
        }
    );
    
    // Continue normal execution...
}
```

### Advanced Usage

```cpp
// Hook a specific thread
HANDLE thread_handle = /* target thread */;
hwbp::get().hook(
    thread_handle,
    target_address,
    callback_function,
    true,   // Enable automatic repatching
    true    // Enable garbage collection for stealth
);
```

## ⚙️ Technical Details

### How it Works

1. **Setup**: Installs a vectored exception handler to catch hardware breakpoint exceptions
2. **Hooking**: Sets a debug register to the target address with execution condition
3. **Execution**: When the CPU executes the instruction at the breakpoint address, it triggers an exception
4. **Handling**: The exception handler calls your custom callback function
5. **Repatching**: The system automatically re-enables the breakpoint after execution

### Debug Registers Used

- **DR0-DR3**: Used to store breakpoint addresses (up to 4 simultaneous breakpoints)
- **DR6**: Debug status register (used to identify which breakpoint was triggered)
- **DR7**: Debug control register (controls breakpoint conditions)

## ⚠️ Limitations

- Maximum of 4 hardware breakpoints per thread (CPU limitation)
- x86/x64 Windows systems only
- Requires appropriate process access rights

## 🔒 Security Considerations

This library uses hardware breakpoints which are:
- More difficult to detect than software breakpoints (which modify code)
- Not affected by code integrity checks
- Thread-specific, allowing for targeted hooking

The optional garbage collection feature helps prevent detection by removing hooks when they're no longer needed.


## ⚡ Performance

Hardware breakpoints have minimal performance impact compared to other hooking methods. They're ideal for scenarios where you need to:

- Hook functions in memory-protected regions
- Avoid modifying code in memory
- Implement hooks that are difficult to detect
- Hook specific threads without affecting others
