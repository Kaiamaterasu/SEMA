const std = @import("std");

// Keep this table intentionally small and conservative; expand as needed.
pub fn syscallName(num: u64) ?[]const u8 {
    return switch (num) {
        0 => "read",
        1 => "write",
        2 => "open",
        3 => "close",
        9 => "mmap",
        10 => "mprotect",
        11 => "munmap",
        12 => "brk",
        39 => "getpid",
        60 => "exit",
        231 => "exit_group",
        257 => "openat",
        158 => "arch_prctl",
        else => null,
    };
}

pub fn syscallArgsDesc(name: []const u8) []const u8 {
    // Deterministic, intentionally incomplete.
    if (std.mem.eql(u8, name, "read")) return "rdi (fd), rsi (buffer), rdx (length)";
    if (std.mem.eql(u8, name, "write")) return "rdi (fd), rsi (buffer), rdx (length)";
    if (std.mem.eql(u8, name, "exit") or std.mem.eql(u8, name, "exit_group")) return "rdi (exit_code)";
    if (std.mem.eql(u8, name, "close")) return "rdi (fd)";
    if (std.mem.eql(u8, name, "open")) return "rdi (path), rsi (flags), rdx (mode)";
    if (std.mem.eql(u8, name, "openat")) return "rdi (dirfd), rsi (path), rdx (flags), r10 (mode)";
    if (std.mem.eql(u8, name, "mmap")) return "rdi (addr), rsi (len), rdx (prot), r10 (flags), r8 (fd), r9 (offset)";
    return "rdi, rsi, rdx, r10, r8, r9 (calling convention)";
}

pub fn syscallDesc(name: []const u8) []const u8 {
    if (std.mem.eql(u8, name, "read")) return "The CPU requests the kernel to read bytes from a file descriptor.";
    if (std.mem.eql(u8, name, "write")) return "The CPU requests the kernel to write bytes to a file descriptor.";
    if (std.mem.eql(u8, name, "exit") or std.mem.eql(u8, name, "exit_group")) return "The CPU requests the kernel to terminate the process.";
    if (std.mem.eql(u8, name, "open") or std.mem.eql(u8, name, "openat")) return "The CPU requests the kernel to open a file and return a file descriptor.";
    if (std.mem.eql(u8, name, "close")) return "The CPU requests the kernel to close a file descriptor.";
    if (std.mem.eql(u8, name, "mmap")) return "The CPU requests the kernel to map memory into the process address space.";
    return "The CPU requests an operating system service from the kernel.";
}

// Conditional jump meanings are deterministic and mnemonic-based.
// This is intentionally explicit (no reliance on instruction decoding beyond the mnemonic).
pub fn jccCondition(mnemonic: []const u8) ?[]const u8 {
    // Equality / zero
    if (std.mem.eql(u8, mnemonic, "je") or std.mem.eql(u8, mnemonic, "jz")) return "ZF == 1 (equal/zero)";
    if (std.mem.eql(u8, mnemonic, "jne") or std.mem.eql(u8, mnemonic, "jnz")) return "ZF == 0 (not equal/nonzero)";

    // Signed comparisons
    if (std.mem.eql(u8, mnemonic, "jg") or std.mem.eql(u8, mnemonic, "jnle")) return "ZF == 0 and SF == OF (signed >)";
    if (std.mem.eql(u8, mnemonic, "jge") or std.mem.eql(u8, mnemonic, "jnl")) return "SF == OF (signed >=)";
    if (std.mem.eql(u8, mnemonic, "jl") or std.mem.eql(u8, mnemonic, "jnge")) return "SF != OF (signed <)";
    if (std.mem.eql(u8, mnemonic, "jle") or std.mem.eql(u8, mnemonic, "jng")) return "ZF == 1 or SF != OF (signed <=)";

    // Unsigned comparisons
    if (std.mem.eql(u8, mnemonic, "ja") or std.mem.eql(u8, mnemonic, "jnbe")) return "CF == 0 and ZF == 0 (unsigned >)";
    if (std.mem.eql(u8, mnemonic, "jae") or std.mem.eql(u8, mnemonic, "jnb") or std.mem.eql(u8, mnemonic, "jnc")) return "CF == 0 (unsigned >=)";
    if (std.mem.eql(u8, mnemonic, "jb") or std.mem.eql(u8, mnemonic, "jnae") or std.mem.eql(u8, mnemonic, "jc")) return "CF == 1 (unsigned <)";
    if (std.mem.eql(u8, mnemonic, "jbe") or std.mem.eql(u8, mnemonic, "jna")) return "CF == 1 or ZF == 1 (unsigned <=)";

    // Sign
    if (std.mem.eql(u8, mnemonic, "js")) return "SF == 1 (negative)";
    if (std.mem.eql(u8, mnemonic, "jns")) return "SF == 0 (non-negative)";

    // Overflow
    if (std.mem.eql(u8, mnemonic, "jo")) return "OF == 1 (overflow)";
    if (std.mem.eql(u8, mnemonic, "jno")) return "OF == 0 (no overflow)";

    // Parity
    if (std.mem.eql(u8, mnemonic, "jp") or std.mem.eql(u8, mnemonic, "jpe")) return "PF == 1 (parity even)";
    if (std.mem.eql(u8, mnemonic, "jnp") or std.mem.eql(u8, mnemonic, "jpo")) return "PF == 0 (parity odd)";

    // Carry
    if (std.mem.eql(u8, mnemonic, "jc")) return "CF == 1 (carry)";
    if (std.mem.eql(u8, mnemonic, "jnc")) return "CF == 0 (no carry)";

    return null;
}
