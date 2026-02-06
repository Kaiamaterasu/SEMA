

const c = @cImport({
    @cInclude("capstone/capstone.h");
});

const x86_64 = @import("x86_64.zig");

const Elf = struct {
    pub const EI_NIDENT: usize = 16;

    pub const Elf64_Ehdr = extern struct {
        e_ident: [EI_NIDENT]u8,
        e_type: u16,
        e_machine: u16,
        e_version: u32,
        e_entry: u64,
        e_phoff: u64,
        e_shoff: u64,
        e_flags: u32,
        e_ehsize: u16,
        e_phentsize: u16,
        e_phnum: u16,
        e_shentsize: u16,
        e_shnum: u16,
        e_shstrndx: u16,
    };

    pub const Elf64_Shdr = extern struct {
        sh_name: u32,
        sh_type: u32,
        sh_flags: u64,
        sh_addr: u64,
        sh_offset: u64,
        sh_size: u64,
        sh_link: u32,
        sh_info: u32,
        sh_addralign: u64,
        sh_entsize: u64,
    };

    pub const Elf64_Sym = extern struct {
        st_name: u32,
        st_info: u8,
        st_other: u8,
        st_shndx: u16,
        st_value: u64,
        st_size: u64,
    };

    pub const Section = struct {
        name: []const u8,
        addr: u64,
        bytes: []const u8,
    };

    pub const FuncSym = struct {
        name: []const u8,
        addr: u64,
        size: u64,
    };

    pub const Parsed = struct {
        entry: u64,
        text: ?Section,
        data: ?Section,
        rodata: ?Section,
        funcs: []FuncSym,
    };

    fn readStruct(comptime T: type, bytes: []const u8, off: usize) !T {
        if (off + @sizeOf(T) > bytes.len) return error.Truncated;
        var out: T = undefined;
        @memcpy(std.mem.asBytes(&out), bytes[off .. off + @sizeOf(T)]);
        return out;
    }

    fn cStr(bytes: []const u8, off: usize) []const u8 {
        if (off >= bytes.len) return "";
        const rest = bytes[off..];
        const end = std.mem.indexOfScalar(u8, rest, 0) orelse rest.len;
        return rest[0..end];
    }

    fn symType(st_info: u8) u8 {
        return st_info & 0x0f;
    }

    pub fn parse(alloc: std.mem.Allocator, file_bytes: []const u8) !Parsed {
        const ehdr = try readStruct(Elf64_Ehdr, file_bytes, 0);

        if (!(ehdr.e_ident[0] == 0x7f and ehdr.e_ident[1] == 'E' and ehdr.e_ident[2] == 'L' and ehdr.e_ident[3] == 'F')) {
            return error.NotElf;
        }
        // ELFCLASS64 = 2
        if (ehdr.e_ident[4] != 2) return error.NotElf64;
        // EM_X86_64 = 62
        if (ehdr.e_machine != 62) return error.NotX8664;

        if (ehdr.e_shoff == 0 or ehdr.e_shentsize == 0 or ehdr.e_shnum == 0) {
            return error.MissingSectionHeaders;
        }

        const shoff: usize = @intCast(ehdr.e_shoff);
        const shentsize: usize = @intCast(ehdr.e_shentsize);
        const shnum: usize = @intCast(ehdr.e_shnum);

        if (shoff + shentsize * shnum > file_bytes.len) return error.Truncated;

        // Load section headers
        var shdrs = try alloc.alloc(Elf64_Shdr, shnum);
        defer alloc.free(shdrs);
        for (0..shnum) |i| {
            const off = shoff + i * shentsize;
            shdrs[i] = try readStruct(Elf64_Shdr, file_bytes, off);
        }

        if (ehdr.e_shstrndx >= shnum) return error.BadShstrndx;
        const shstr = shdrs[ehdr.e_shstrndx];
        const shstr_off: usize = @intCast(shstr.sh_offset);
        const shstr_size: usize = @intCast(shstr.sh_size);
        if (shstr_off + shstr_size > file_bytes.len) return error.Truncated;
        const shstrtab = file_bytes[shstr_off .. shstr_off + shstr_size];

        var text: ?Section = null;
        var data: ?Section = null;
        var rodata: ?Section = null;

        var symtab_index: ?usize = null;
        var dynsym_index: ?usize = null;

        // SHT_SYMTAB = 2, SHT_DYNSYM = 11
        for (shdrs, 0..) |sh, i| {
            const name = cStr(shstrtab, sh.sh_name);
            const off: usize = @intCast(sh.sh_offset);
            const size: usize = @intCast(sh.sh_size);
            if (off + size > file_bytes.len) continue;

            if (std.mem.eql(u8, name, ".text")) {
                text = .{ .name = name, .addr = sh.sh_addr, .bytes = file_bytes[off .. off + size] };
            } else if (std.mem.eql(u8, name, ".data")) {
                data = .{ .name = name, .addr = sh.sh_addr, .bytes = file_bytes[off .. off + size] };
            } else if (std.mem.eql(u8, name, ".rodata")) {
                rodata = .{ .name = name, .addr = sh.sh_addr, .bytes = file_bytes[off .. off + size] };
            }

            if (sh.sh_type == 2) symtab_index = i;
            if (sh.sh_type == 11) dynsym_index = i;
        }

        // Collect function symbols from symtab/dynsym if present.
        var funcs_list = std.ArrayList(FuncSym).init(alloc);
        errdefer funcs_list.deinit();

        const maybe_parse_syms = struct {
            fn go(alloc2: std.mem.Allocator, file: []const u8, shdrs2: []const Elf64_Shdr, sec_index: usize, out: *std.ArrayList(FuncSym)) !void {
                const sec = shdrs2[sec_index];
                const off: usize = @intCast(sec.sh_offset);
                const size: usize = @intCast(sec.sh_size);
                const entsize: usize = @intCast(sec.sh_entsize);
                if (entsize == 0) return;
                if (off + size > file.len) return;

                const link = sec.sh_link;
                if (link >= shdrs2.len) return;
                const strsec = shdrs2[link];
                const stroff: usize = @intCast(strsec.sh_offset);
                const strsize: usize = @intCast(strsec.sh_size);
                if (stroff + strsize > file.len) return;
                const strtab = file[stroff .. stroff + strsize];

                const count = size / entsize;
                var i: usize = 0;
                while (i < count) : (i += 1) {
                    const sym_off = off + i * entsize;
                    const sym = try readStruct(Elf64_Sym, file, sym_off);
                    // STT_FUNC = 2
                    if (symType(sym.st_info) != 2) continue;
                    if (sym.st_value == 0) continue;

                    const nm = cStr(strtab, sym.st_name);
                    const name = if (nm.len == 0) "(unnamed)" else nm;
                    try out.append(.{ .name = try alloc2.dupe(u8, name), .addr = sym.st_value, .size = sym.st_size });
                }
            }
        }.go;

        if (symtab_index) |idx| try maybe_parse_syms(alloc, file_bytes, shdrs, idx, &funcs_list);
        if (dynsym_index) |idx| try maybe_parse_syms(alloc, file_bytes, shdrs, idx, &funcs_list);

        // Sort funcs by address for deterministic output.
        std.sort.heap(FuncSym, funcs_list.items, {}, struct {
            fn lessThan(_: void, a: FuncSym, b: FuncSym) bool {
                if (a.addr != b.addr) return a.addr < b.addr;
                return std.mem.lessThan(u8, a.name, b.name);
            }
        }.lessThan);

        return .{
            .entry = ehdr.e_entry,
            .text = text,
            .data = data,
            .rodata = rodata,
            .funcs = try funcs_list.toOwnedSlice(),
        };
    }
};

const Category = enum {
    data_movement,
    arithmetic_logic,
    control_flow,
    stack,
    system_boundary,
    other,
};

fn classify(mnemonic: []const u8, op_str: []const u8) Category {
    // Keep deterministic and explicit: fixed string comparisons only.
    // Treat stack pointer adjustments as stack manipulation.
    if ((std.mem.eql(u8, mnemonic, "sub") or std.mem.eql(u8, mnemonic, "add")) and
        (std.mem.startsWith(u8, op_str, "rsp,") or std.mem.startsWith(u8, op_str, "esp,")))
    {
        return .stack;
    }

    if (std.mem.eql(u8, mnemonic, "mov") or std.mem.eql(u8, mnemonic, "movabs") or std.mem.eql(u8, mnemonic, "lea") or std.mem.eql(u8, mnemonic, "xchg")) return .data_movement;

    if (std.mem.eql(u8, mnemonic, "add") or std.mem.eql(u8, mnemonic, "sub") or std.mem.eql(u8, mnemonic, "xor") or std.mem.eql(u8, mnemonic, "and") or std.mem.eql(u8, mnemonic, "or") or std.mem.eql(u8, mnemonic, "imul") or std.mem.eql(u8, mnemonic, "idiv") or std.mem.eql(u8, mnemonic, "mul") or std.mem.eql(u8, mnemonic, "div") or std.mem.eql(u8, mnemonic, "cmp") or std.mem.eql(u8, mnemonic, "test")) return .arithmetic_logic;

    if (std.mem.eql(u8, mnemonic, "call") or std.mem.eql(u8, mnemonic, "ret") or std.mem.eql(u8, mnemonic, "jmp")) return .control_flow;
    if (mnemonic.len >= 1 and mnemonic[0] == 'j') return .control_flow; // jcc

    if (std.mem.eql(u8, mnemonic, "push") or std.mem.eql(u8, mnemonic, "pop") or std.mem.eql(u8, mnemonic, "enter") or std.mem.eql(u8, mnemonic, "leave")) return .stack;

    if (std.mem.eql(u8, mnemonic, "syscall") or std.mem.eql(u8, mnemonic, "sysenter") or std.mem.eql(u8, mnemonic, "int")) return .system_boundary;

    return .other;
}

fn categoryName(cat: Category) []const u8 {
    return switch (cat) {
        .data_movement => "data movement",
        .arithmetic_logic => "arithmetic / logic",
        .control_flow => "control flow",
        .stack => "stack manipulation",
        .system_boundary => "system boundary",
        .other => "other",
    };
}

fn renderSemantics(alloc: std.mem.Allocator, inst: *const c.cs_insn) ![]const u8 {
    // Deterministic rule-based templates.
    const mnem = std.mem.sliceTo(inst.mnemonic[0..], 0);
    const ops = std.mem.sliceTo(inst.op_str[0..], 0);

    if (std.mem.eql(u8, mnem, "sub") and (std.mem.startsWith(u8, ops, "rsp,") or std.mem.startsWith(u8, ops, "esp,"))) {
        return std.fmt.allocPrint(alloc, "The CPU adjusts the stack pointer downward to reserve stack space: {s}.", .{ops});
    }
    if (std.mem.eql(u8, mnem, "add") and (std.mem.startsWith(u8, ops, "rsp,") or std.mem.startsWith(u8, ops, "esp,"))) {
        return std.fmt.allocPrint(alloc, "The CPU adjusts the stack pointer upward to release stack space: {s}.", .{ops});
    }

    if (std.mem.eql(u8, mnem, "mov") or std.mem.eql(u8, mnem, "movabs")) {
        return std.fmt.allocPrint(alloc, "The CPU copies a value using mov: {s}.", .{ops});
    }
    if (std.mem.eql(u8, mnem, "lea")) {
        return std.fmt.allocPrint(alloc, "The CPU computes an effective address and writes it: {s}.", .{ops});
    }
    if (std.mem.eql(u8, mnem, "cmp")) {
        return std.fmt.allocPrint(alloc, "The CPU compares operands and updates flags without storing a result: {s}.", .{ops});
    }
    if (std.mem.eql(u8, mnem, "test")) {
        return std.fmt.allocPrint(alloc, "The CPU performs a bitwise test and updates flags without storing a result: {s}.", .{ops});
    }
    if (std.mem.eql(u8, mnem, "call")) {
        return std.fmt.allocPrint(alloc, "The CPU pushes a return address and transfers control to a call target: {s}.", .{ops});
    }
    if (std.mem.eql(u8, mnem, "ret")) {
        return std.fmt.allocPrint(alloc, "The CPU pops a return address and resumes execution at that address.", .{});
    }
    if (std.mem.eql(u8, mnem, "jmp")) {
        return std.fmt.allocPrint(alloc, "The CPU unconditionally transfers execution to: {s}.", .{ops});
    }
    if (mnem.len >= 1 and mnem[0] == 'j') {
        if (x86_64.jccCondition(mnem)) |cond| {
            return std.fmt.allocPrint(alloc, "The CPU checks condition flags ({s}) and conditionally transfers execution using {s}: {s}.", .{ cond, mnem, ops });
        }
        return std.fmt.allocPrint(alloc, "The CPU conditionally transfers execution based on flags using {s}: {s}.", .{ mnem, ops });
    }
    if (std.mem.eql(u8, mnem, "syscall")) {
        return std.fmt.allocPrint(alloc, "The CPU transitions to kernel mode to request an operating system service.", .{});
    }
    if (std.mem.eql(u8, mnem, "push")) {
        return std.fmt.allocPrint(alloc, "The CPU decrements the stack pointer and stores a value on the stack: {s}.", .{ops});
    }
    if (std.mem.eql(u8, mnem, "pop")) {
        return std.fmt.allocPrint(alloc, "The CPU loads a value from the stack and increments the stack pointer: {s}.", .{ops});
    }

    return std.fmt.allocPrint(alloc, "Unknown/unclear semantics for this instruction pattern: {s} {s}.", .{ mnem, ops });
}

const Call = struct {
    kind: enum { direct, indirect },
    target: u64,
};

const SyscallEvent = struct {
    addr: u64,
    number: ?u64,
};

const BranchEdge = struct {
    src: u64,
    dst: ?u64,
    mnemonic: []const u8,
};

const Ref = struct {
    insn_addr: u64,
    func_index: ?usize,
};

const StringEntry = struct {
    addr: u64,
    value: []const u8,
    refs: std.ArrayList(Ref),
};

const FuncOut = struct {
    name: ?[]const u8,
    inferred_name: bool,
    start: u64,
    end: u64,
    is_entry: bool,
    calls: std.ArrayList(Call),
};

fn syscallName(num: u64) ?[]const u8 {
    return x86_64.syscallName(num);
}

fn syscallArgsDesc(name: []const u8) []const u8 {
    return x86_64.syscallArgsDesc(name);
}

fn syscallDesc(name: []const u8) []const u8 {
    return x86_64.syscallDesc(name);
}

fn isPrintableAscii(b: u8) bool {
    return b >= 0x20 and b <= 0x7e;
}

fn escapeForQuotes(alloc: std.mem.Allocator, s: []const u8) ![]const u8 {
    var out = std.ArrayList(u8).init(alloc);
    errdefer out.deinit();

    for (s) |ch| {
        switch (ch) {
            '\\' => try out.appendSlice("\\\\"),
            '"' => try out.appendSlice("\\\""),
            else => try out.append(ch),
        }
    }

    return try out.toOwnedSlice();
}

fn extractStrings(alloc: std.mem.Allocator, ro: Elf.Section) ![]StringEntry {
    var list = std.ArrayList(StringEntry).init(alloc);
    errdefer {
        for (list.items) |*e| {
            alloc.free(e.value);
            e.refs.deinit();
        }
        list.deinit();
    }

    var i: usize = 0;
    while (i < ro.bytes.len) : (i += 1) {
        if (!isPrintableAscii(ro.bytes[i])) continue;

        const start = i;
        while (i < ro.bytes.len and isPrintableAscii(ro.bytes[i])) : (i += 1) {}

        if (i >= ro.bytes.len or ro.bytes[i] != 0) continue; // must be NUL-terminated

        const len = i - start;
        if (len < 4) continue;

        const s = ro.bytes[start .. start + len];
        const dup = try alloc.dupe(u8, s);
        try list.append(.{
            .addr = ro.addr + start,
            .value = dup,
            .refs = std.ArrayList(Ref).init(alloc),
        });
    }

    return try list.toOwnedSlice();
}

fn findStringIndex(strings: []const StringEntry, addr: u64) ?usize {
    // strings are in increasing address order.
    var lo: usize = 0;
    var hi: usize = strings.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const s = strings[mid];
        const start = s.addr;
        const end = s.addr + s.value.len;

        if (addr < start) {
            hi = mid;
        } else if (addr >= end) {
            lo = mid + 1;
        } else {
            return mid;
        }
    }
    return null;
}

fn nameForFunc(f: FuncOut) []const u8 {
    return f.name orelse "(unnamed)";
}

fn disassembleAndPrint(
    alloc: std.mem.Allocator,
    text_addr: u64,
    text_bytes: []const u8,
    rodata: ?Elf.Section,
    data: ?Elf.Section,
    funcs_in: []const Elf.FuncSym,
    entry_addr: u64,
) !void {
    var handle: c.csh = 0;
    if (c.cs_open(c.CS_ARCH_X86, c.CS_MODE_64, &handle) != c.CS_ERR_OK) return error.CapstoneInitFailed;
    defer _ = c.cs_close(&handle);

    _ = c.cs_option(handle, c.CS_OPT_DETAIL, c.CS_OPT_ON);

    var insn_ptr: [*c]c.cs_insn = null;
    const count = c.cs_disasm(handle, text_bytes.ptr, text_bytes.len, text_addr, 0, &insn_ptr);
    if (count == 0) return error.DisasmFailed;
    defer c.cs_free(insn_ptr, count);

    // cs_disasm returns a C pointer type which Zig models as allowzero; after count>0 we treat it as non-null.
    const insns: [*]c.cs_insn = @ptrCast(insn_ptr);

    const total: usize = @intCast(count);
    const text_end = text_addr + text_bytes.len;

    // ----- Build function list (symbols + best-effort end ranges) -----
    var funcs = std.ArrayList(FuncOut).init(alloc);
    defer {
        for (funcs.items) |*f| f.calls.deinit();
        funcs.deinit();
    }

    // Some binaries place special functions (e.g. _fini) outside the .text section.
    // We disassemble only .text, so only include symbol functions that fall within the
    // disassembled range. This avoids producing invalid ranges where end < start.
    var funcs_in_text = std.ArrayList(Elf.FuncSym).init(alloc);
    defer funcs_in_text.deinit();
    if (funcs_in.len != 0) {
        for (funcs_in) |f| {
            if (f.addr >= text_addr and f.addr < text_end) {
                try funcs_in_text.append(f);
            }
        }
    }

    const funcs_sym: []const Elf.FuncSym = if (funcs_in_text.items.len != 0) funcs_in_text.items else &[_]Elf.FuncSym{};

    if (funcs_sym.len == 0) {
        // Heuristic function starts for stripped binaries.
        // Deterministic sources:
        // - entry point (if inside .text, otherwise .text start)
        // - direct call immediate targets (inside .text)
        // - classic prologue pattern: push rbp; mov rbp, rsp
        var starts = std.ArrayList(u64).init(alloc);
        defer starts.deinit();

        const entry_in_text = if (entry_addr >= text_addr and entry_addr < text_end) entry_addr else text_addr;
        try starts.append(entry_in_text);

        var ii: usize = 0;
        while (ii < total) : (ii += 1) {
            const inst = &insns[ii];
            const mnem = std.mem.sliceTo(inst.mnemonic[0..], 0);
            const ops = std.mem.sliceTo(inst.op_str[0..], 0);

            if (std.mem.eql(u8, mnem, "call") and inst.detail != null) {
                const x86 = inst.detail.*.unnamed_0.x86;
                if (x86.op_count >= 1 and x86.operands[0].type == c.X86_OP_IMM) {
                    const target: u64 = @intCast(@as(i128, x86.operands[0].unnamed_0.imm));
                    if (target >= text_addr and target < text_end) {
                        try starts.append(target);
                    }
                }
            }

            // Prologue: push rbp; mov rbp, rsp
            if (std.mem.eql(u8, mnem, "push") and std.mem.eql(u8, std.mem.trim(u8, ops, " \t"), "rbp")) {
                if (ii + 1 < total) {
                    const n = &insns[ii + 1];
                    const nm = std.mem.sliceTo(n.mnemonic[0..], 0);
                    const no = std.mem.sliceTo(n.op_str[0..], 0);
                    if (std.mem.eql(u8, nm, "mov")) {
                        const t = std.mem.trim(u8, no, " \t");
                        if (std.mem.startsWith(u8, t, "rbp, rsp") or std.mem.startsWith(u8, t, "rbp,rsp")) {
                            if (inst.address >= text_addr and inst.address < text_end) {
                                try starts.append(inst.address);
                            }
                        }
                    }
                }
            }
        }

        std.sort.heap(u64, starts.items, {}, std.sort.asc(u64));

        // Dedupe starts in-place.
        var uniq = std.ArrayList(u64).init(alloc);
        defer uniq.deinit();
        for (starts.items) |s| {
            if (uniq.items.len == 0 or uniq.items[uniq.items.len - 1] != s) {
                try uniq.append(s);
            }
        }

        for (uniq.items, 0..) |s, idx| {
            const end = if (idx + 1 < uniq.items.len) uniq.items[idx + 1] else text_end;
            try funcs.append(.{
                .name = null,
                .inferred_name = true,
                .start = s,
                .end = end,
                .is_entry = (s == entry_in_text),
                .calls = std.ArrayList(Call).init(alloc),
            });
        }
    } else {
        for (funcs_sym, 0..) |f, idx| {
            const start = f.addr;
            var end: u64 = if (f.size != 0) start + f.size else text_end;
            if (f.size == 0 and idx + 1 < funcs_sym.len) end = funcs_sym[idx + 1].addr;
            if (end > text_end) end = text_end;
            if (end < start) end = start;
            const is_entry = (start == entry_addr) or std.mem.eql(u8, f.name, "_start");

            try funcs.append(.{
                .name = f.name,
                .inferred_name = false,
                .start = start,
                .end = end,
                .is_entry = is_entry,
                .calls = std.ArrayList(Call).init(alloc),
            });
        }
    }

    var func_by_addr = std.AutoHashMap(u64, usize).init(alloc);
    defer func_by_addr.deinit();
    for (funcs.items, 0..) |f, idx| {
        _ = try func_by_addr.put(f.start, idx);
    }

    // ----- Strings -----
    var strings: []StringEntry = &[_]StringEntry{};
    var have_strings = false;
    if (rodata) |ro| {
        strings = try extractStrings(alloc, ro);
        have_strings = true;
    }
    defer if (have_strings) {
        for (strings) |*e| {
            alloc.free(e.value);
            e.refs.deinit();
        }
        alloc.free(strings);
    };

    // ----- Stats and events -----
    var per_cat: [6]usize = .{0} ** 6;
    var syscalls = std.ArrayList(SyscallEvent).init(alloc);
    defer syscalls.deinit();

    var cond_branches = std.ArrayList(BranchEdge).init(alloc);
    defer cond_branches.deinit();

    var uncond_jumps = std.ArrayList(BranchEdge).init(alloc);
    defer uncond_jumps.deinit();

    var loop_backedges = std.ArrayList(BranchEdge).init(alloc);
    defer loop_backedges.deinit();

    const DataRef = struct {
        insn_addr: u64,
        target: u64,
        func_index: ?usize,
    };

    var data_refs = std.ArrayList(DataRef).init(alloc);
    defer data_refs.deinit();

    var cmp_count: usize = 0;
    var test_count: usize = 0;

    var imm_seen = std.AutoHashMap(i64, void).init(alloc);
    defer imm_seen.deinit();
    var imm_list = std.ArrayList(i64).init(alloc);
    defer imm_list.deinit();

    // Stack tracking is best-effort and linear (does not account for branches).
    const func_count = funcs.items.len;
    var stack_cur = try alloc.alloc(i64, func_count);
    var stack_min = try alloc.alloc(i64, func_count);
    var stack_ops = try alloc.alloc(usize, func_count);
    defer {
        alloc.free(stack_cur);
        alloc.free(stack_min);
        alloc.free(stack_ops);
    }
    @memset(stack_cur, 0);
    @memset(stack_min, 0);
    @memset(stack_ops, 0);

    // Track potential syscall number set in RAX/EAX.
    var last_rax_imm: ?u64 = null;

    // Scan instructions once to collect counts, calls, syscalls, control-flow, string/data refs, and stack behavior.
    var i: usize = 0;
    while (i < total) : (i += 1) {
        const inst = &insns[i];
        const mnem = std.mem.sliceTo(inst.mnemonic[0..], 0);
        const ops = std.mem.sliceTo(inst.op_str[0..], 0);

        if (std.mem.eql(u8, mnem, "cmp")) cmp_count += 1;
        if (std.mem.eql(u8, mnem, "test")) test_count += 1;

        const cat = classify(mnem, ops);
        per_cat[@intFromEnum(cat)] += 1;

        // Determine containing function (best-effort, range-based).
        var func_index: ?usize = null;
        if (funcs.items.len != 0) {
            // funcs are in increasing start order.
            var lo: usize = 0;
            var hi: usize = funcs.items.len;
            while (lo < hi) {
                const mid = lo + (hi - lo) / 2;
                const f = funcs.items[mid];
                if (inst.address < f.start) {
                    hi = mid;
                } else if (inst.address >= f.end) {
                    lo = mid + 1;
                } else {
                    func_index = mid;
                    break;
                }
            }
        }

        // Operand decoding (only reliable when detail is available).
        const detail_ptr = inst.detail;
        if (detail_ptr != null) {
            const detail = detail_ptr.*;
            const x86 = detail.unnamed_0.x86;

            // Operand-level scanning: constants, RIP-relative memory targets (rodata/data), and stack effects.
            var opi: usize = 0;
            while (opi < x86.op_count) : (opi += 1) {
                const op = x86.operands[opi];

                if (op.type == c.X86_OP_IMM) {
                    const v: i64 = op.unnamed_0.imm;
                    const gop = try imm_seen.getOrPut(v);
                    if (!gop.found_existing) try imm_list.append(v);
                    continue;
                }

                if (op.type == c.X86_OP_MEM and op.unnamed_0.mem.base == c.X86_REG_RIP) {
                    const target_signed: i128 = @as(i128, @intCast(inst.address)) + @as(i128, @intCast(inst.size)) + @as(i128, op.unnamed_0.mem.disp);
                    if (target_signed < 0) continue;
                    const target: u64 = @intCast(target_signed);

                    if (have_strings and rodata != null) {
                        const ro = rodata.?;
                        if (target >= ro.addr and target < ro.addr + ro.bytes.len) {
                            if (findStringIndex(strings, target)) |sidx| {
                                try strings[sidx].refs.append(.{ .insn_addr = inst.address, .func_index = func_index });
                            }
                        }
                    }

                    if (data != null) {
                        const da = data.?;
                        if (target >= da.addr and target < da.addr + da.bytes.len) {
                            try data_refs.append(.{ .insn_addr = inst.address, .target = target, .func_index = func_index });
                        }
                    }

                    continue;
                }
            }

            // Stack pointer behavior (linear best-effort).
            if (func_index) |fi| {
                var delta: i64 = 0;
                var changed = false;

                if (std.mem.eql(u8, mnem, "push")) {
                    delta = -8;
                    changed = true;
                } else if (std.mem.eql(u8, mnem, "pop")) {
                    delta = 8;
                    changed = true;
                } else if ((std.mem.eql(u8, mnem, "sub") or std.mem.eql(u8, mnem, "add")) and x86.op_count >= 2) {
                    const op0 = x86.operands[0];
                    const op1 = x86.operands[1];
                    if (op0.type == c.X86_OP_REG and op0.unnamed_0.reg == c.X86_REG_RSP and op1.type == c.X86_OP_IMM) {
                        const imm: i64 = op1.unnamed_0.imm;
                        if (std.mem.eql(u8, mnem, "sub")) {
                            delta = -imm;
                        } else {
                            delta = imm;
                        }
                        changed = true;
                    }
                }

                if (changed) {
                    stack_cur[fi] += delta;
                    if (stack_cur[fi] < stack_min[fi]) stack_min[fi] = stack_cur[fi];
                    stack_ops[fi] += 1;
                }
            }

            // Syscall number inference (very conservative).
            var rax_written_known = false;
            if (std.mem.eql(u8, mnem, "mov") or std.mem.eql(u8, mnem, "movabs")) {
                if (x86.op_count >= 2 and x86.operands[0].type == c.X86_OP_REG and x86.operands[1].type == c.X86_OP_IMM) {
                    const dst = x86.operands[0].unnamed_0.reg;
                    if (dst == c.X86_REG_RAX or dst == c.X86_REG_EAX) {
                        last_rax_imm = @intCast(@as(i128, x86.operands[1].unnamed_0.imm));
                        rax_written_known = true;
                    }
                }
            } else if (std.mem.eql(u8, mnem, "xor")) {
                if (x86.op_count >= 2 and x86.operands[0].type == c.X86_OP_REG and x86.operands[1].type == c.X86_OP_REG) {
                    const r0 = x86.operands[0].unnamed_0.reg;
                    const r1 = x86.operands[1].unnamed_0.reg;
                    if ((r0 == c.X86_REG_RAX or r0 == c.X86_REG_EAX) and r0 == r1) {
                        last_rax_imm = 0;
                        rax_written_known = true;
                    }
                }
            }

            if (!rax_written_known and detail.regs_write_count != 0) {
                var wi: usize = 0;
                while (wi < detail.regs_write_count) : (wi += 1) {
                    const r = detail.regs_write[wi];
                    if (r == c.X86_REG_RAX or r == c.X86_REG_EAX) {
                        last_rax_imm = null;
                        break;
                    }
                }
            }

            // Calls / control-flow edges.
            if (std.mem.eql(u8, mnem, "call")) {
                if (func_index) |fi| {
                    if (x86.op_count >= 1 and x86.operands[0].type == c.X86_OP_IMM) {
                        const target: u64 = @intCast(@as(i128, x86.operands[0].unnamed_0.imm));
                        // Dedupe (small linear scan, deterministic).
                        var seen = false;
                        for (funcs.items[fi].calls.items) |c0| {
                            if (c0.kind == .direct and c0.target == target) {
                                seen = true;
                                break;
                            }
                        }
                        if (!seen) try funcs.items[fi].calls.append(.{ .kind = .direct, .target = target });
                    } else {
                        var seen_indirect = false;
                        for (funcs.items[fi].calls.items) |c0| {
                            if (c0.kind == .indirect) {
                                seen_indirect = true;
                                break;
                            }
                        }
                        if (!seen_indirect) try funcs.items[fi].calls.append(.{ .kind = .indirect, .target = 0 });
                    }
                }
            }

            if (std.mem.eql(u8, mnem, "jmp") or (mnem.len >= 1 and mnem[0] == 'j')) {
                var dst: ?u64 = null;
                if (x86.op_count >= 1 and x86.operands[0].type == c.X86_OP_IMM) {
                    dst = @intCast(@as(i128, x86.operands[0].unnamed_0.imm));
                }

                const edge: BranchEdge = .{ .src = inst.address, .dst = dst, .mnemonic = mnem };

                if (std.mem.eql(u8, mnem, "jmp")) {
                    try uncond_jumps.append(edge);
                } else {
                    try cond_branches.append(edge);
                }

                if (dst) |d| {
                    if (d < inst.address) {
                        try loop_backedges.append(edge);
                    }
                }
            }

            if (std.mem.eql(u8, mnem, "syscall")) {
                try syscalls.append(.{ .addr = inst.address, .number = last_rax_imm });
            }
        } else {
            // No detail: cannot infer syscall numbers, call targets, or memory refs.
            if (std.mem.eql(u8, mnem, "syscall")) {
                try syscalls.append(.{ .addr = inst.address, .number = null });
            }
        }
    }

    const w = std.io.getStdOut().writer();

    try w.print("Architecture: x86-64\n\n", .{});

    try w.print("Instruction Overview:\n", .{});
    try w.print("- Total instructions: {d}\n", .{total});
    var cati: usize = 0;
    while (cati < per_cat.len) : (cati += 1) {
        const cat: Category = @enumFromInt(cati);
        try w.print("- {s}: {d}\n", .{ categoryName(cat), per_cat[cati] });
    }
    try w.print("\nCategory meanings:\n", .{});
    try w.print("- data movement: The CPU transfers values or addresses between registers and memory.\n", .{});
    try w.print("- arithmetic / logic: The CPU performs calculations/bit-ops and updates flags.\n", .{});
    try w.print("- control flow: The CPU changes the instruction pointer (jumps, calls, returns).\n", .{});
    try w.print("- stack manipulation: The CPU changes RSP or uses the stack for storage/calls.\n", .{});
    try w.print("- system boundary: The CPU crosses into the kernel or privileged boundary (e.g. syscall).\n", .{});
    try w.print("- other: Instructions not yet categorized.\n\n", .{});

    // ----- Functions -----
    try w.print("Functions:\n", .{});
    try w.print("Functions detected: {d}\n\n", .{funcs.items.len});

    for (funcs.items) |f| {
        if (f.name) |nm| {
            try w.print("Function: {s}\n", .{nm});
        } else {
            try w.print("Function at 0x{x} (unnamed)\n", .{f.start});
            if (f.inferred_name) {
                try w.print("(Name inferred via heuristic)\n", .{});
            }
        }

        try w.print("- Start address: 0x{x}\n", .{f.start});
        try w.print("- End address: 0x{x}\n", .{f.end});

        const leafness = if (f.calls.items.len == 0) "leaf" else "non-leaf";
        const entryness = if (f.is_entry) "entry point" else "internal";
        try w.print("- Type: {s}, {s}\n", .{ entryness, leafness });

        if (f.calls.items.len == 0) {
            try w.print("- Calls: none\n\n", .{});
        } else {
            try w.print("- Calls: ", .{});
            for (f.calls.items, 0..) |cl, ci| {
                if (ci != 0) try w.print(", ", .{});
                if (cl.kind == .indirect) {
                    try w.print("unknown (indirect)", .{});
                } else {
                    if (func_by_addr.get(cl.target)) |tidx| {
                        try w.print("{s}", .{nameForFunc(funcs.items[tidx])});
                    } else {
                        try w.print("0x{x}", .{cl.target});
                    }
                }
            }
            try w.print("\n\n", .{});
        }
    }

    // ----- CPU Semantics -----
    try w.print("CPU Semantics:\n", .{});

    var current_func: ?usize = null;
    i = 0;
    while (i < total) : (i += 1) {
        const inst = &insns[i];
        const mnem = std.mem.sliceTo(inst.mnemonic[0..], 0);
        const ops = std.mem.sliceTo(inst.op_str[0..], 0);
        const cat = classify(mnem, ops);

        // Best-effort function context header.
        var fi: ?usize = null;
        {
            var lo: usize = 0;
            var hi: usize = funcs.items.len;
            while (lo < hi) {
                const mid = lo + (hi - lo) / 2;
                const f = funcs.items[mid];
                if (inst.address < f.start) {
                    hi = mid;
                } else if (inst.address >= f.end) {
                    lo = mid + 1;
                } else {
                    fi = mid;
                    break;
                }
            }
        }
        if (fi != current_func) {
            current_func = fi;
            if (fi) |idx| {
                const f = funcs.items[idx];
                if (f.name) |nm| {
                    try w.print("\nIn function {s} (0x{x}):\n", .{ nm, f.start });
                } else {
                    try w.print("\nIn function at 0x{x} (unnamed):\n", .{f.start});
                }
            }
        }

        const sem = try renderSemantics(alloc, inst);
        defer alloc.free(sem);

        try w.print("0x{x}: {s} {s}\n", .{ inst.address, mnem, ops });
        try w.print("- Category: {s}\n", .{categoryName(cat)});
        try w.print("- Explanation: {s}\n", .{sem});

        // Extra deterministic context for RIP-relative addressing.
        if (inst.detail != null) {
            const x86 = inst.detail.*.unnamed_0.x86;
            var opi: usize = 0;
            while (opi < x86.op_count) : (opi += 1) {
                const op0 = x86.operands[opi];
                if (op0.type != c.X86_OP_MEM) continue;
                if (op0.unnamed_0.mem.base != c.X86_REG_RIP) continue;

                const target_signed: i128 = @as(i128, @intCast(inst.address)) + @as(i128, @intCast(inst.size)) + @as(i128, op0.unnamed_0.mem.disp);
                if (target_signed < 0) continue;
                const target: u64 = @intCast(target_signed);

                if (std.mem.eql(u8, mnem, "lea")) {
                    try w.print("- Resolved address: 0x{x}\n", .{target});
                } else {
                    // For memory operands, try to describe the target section.
                    var access_desc: []const u8 = "unknown";
                    if ((op0.access & c.CS_AC_READ) != 0 and (op0.access & c.CS_AC_WRITE) != 0) {
                        access_desc = "read+write";
                    } else if ((op0.access & c.CS_AC_READ) != 0) {
                        access_desc = "read";
                    } else if ((op0.access & c.CS_AC_WRITE) != 0) {
                        access_desc = "write";
                    }

                    if (rodata != null) {
                        const ro = rodata.?;
                        if (target >= ro.addr and target < ro.addr + ro.bytes.len) {
                            try w.print("- RIP-relative memory target: 0x{x} (.rodata, {s})\n", .{ target, access_desc });
                            if (have_strings) {
                                if (findStringIndex(strings, target)) |sidx| {
                                    const escaped = try escapeForQuotes(alloc, strings[sidx].value);
                                    defer alloc.free(escaped);
                                    try w.print("- References string: \"{s}\"\n", .{escaped});
                                }
                            }
                            continue;
                        }
                    }

                    if (data != null) {
                        const da = data.?;
                        if (target >= da.addr and target < da.addr + da.bytes.len) {
                            try w.print("- RIP-relative memory target: 0x{x} (.data, {s})\n", .{ target, access_desc });
                            continue;
                        }
                    }

                    try w.print("- RIP-relative memory target: 0x{x} ({s})\n", .{ target, access_desc });
                }
            }
        }

        try w.print("\n", .{});
    }

    // ----- Syscalls -----
    try w.print("Syscalls:\n", .{});
    if (syscalls.items.len == 0) {
        try w.print("(none detected)\n\n", .{});
    } else {
        for (syscalls.items) |sc| {
            if (sc.number) |n| {
                const nm = syscallName(n) orelse "unknown";
                try w.print("Syscall: {s}\n", .{nm});
                try w.print("- Address: 0x{x}\n", .{sc.addr});
                try w.print("- Number: {d}\n", .{n});
                try w.print("- Registers: {s}\n", .{syscallArgsDesc(nm)});
                try w.print("- Description: {s}\n\n", .{syscallDesc(nm)});
            } else {
                try w.print("Syscall: unknown\n", .{});
                try w.print("- Address: 0x{x}\n", .{sc.addr});
                try w.print("- Number: unknown\n", .{});
                try w.print("- Registers: rdi, rsi, rdx, r10, r8, r9 (calling convention)\n", .{});
                try w.print("- Description: The CPU transitions to kernel mode to request an operating system service.\n\n", .{});
            }
        }
    }

    // ----- System interaction (layering clarification) -----
    try w.print("System Interaction:\n", .{});
    if (syscalls.items.len == 0) {
        try w.print("- No direct system call instructions were detected in the disassembled region.\n", .{});
        try w.print("- If the program interacts with the operating system (I/O, process setup, etc.), that interaction likely occurs through external/library calls (e.g. via PLT stubs), not via `syscall` instructions shown here.\n", .{});
        try w.print("- At the CPU level, this looks like ordinary `call` control transfers, not explicit kernel transitions.\n\n", .{});
    } else {
        try w.print("- Direct system call instructions were detected.\n", .{});
        try w.print("- Each `syscall` is a CPU-level transition into the kernel boundary.\n\n", .{});
    }

    // ----- Strings -----
    try w.print("Strings:\n", .{});
    if (!have_strings) {
        try w.print("(no .rodata section found)\n\n", .{});
    } else if (strings.len == 0) {
        try w.print("(no printable NUL-terminated strings found)\n\n", .{});
    } else {
        for (strings) |s| {
            const escaped = try escapeForQuotes(alloc, s.value);
            defer alloc.free(escaped);

            try w.print("String: \"{s}\"\n", .{escaped});
            try w.print("- Address: 0x{x}\n", .{s.addr});
            try w.print("- Section: .rodata\n", .{});

            if (s.refs.items.len == 0) {
                try w.print("- Referenced by: (none)\n", .{});
                try w.print("- Used: no\n\n", .{});
            } else {
                try w.print("- Used: yes\n", .{});
                try w.print("- Referencing instructions: ", .{});
                for (s.refs.items, 0..) |r, ri| {
                    if (ri != 0) try w.print(", ", .{});
                    try w.print("0x{x}", .{r.insn_addr});
                }
                try w.print("\n", .{});

                // Functions referencing (best-effort). Keep output deterministic.
                var func_idxs = std.ArrayList(usize).init(alloc);
                defer func_idxs.deinit();
                for (s.refs.items) |r| {
                    if (r.func_index) |fi| {
                        var seen = false;
                        for (func_idxs.items) |existing| {
                            if (existing == fi) {
                                seen = true;
                                break;
                            }
                        }
                        if (!seen) try func_idxs.append(fi);
                    }
                }

                if (func_idxs.items.len == 0) {
                    try w.print("- Referenced by: unknown\n\n", .{});
                } else {
                    std.sort.heap(usize, func_idxs.items, {}, std.sort.asc(usize));
                    try w.print("- Referenced by: ", .{});
                    for (func_idxs.items, 0..) |fi, idx| {
                        if (idx != 0) try w.print(", ", .{});
                        const f = funcs.items[fi];
                        if (f.name) |nm| {
                            try w.print("{s}", .{nm});
                        } else {
                            try w.print("0x{x}", .{f.start});
                        }
                    }
                    try w.print("\n\n", .{});
                }
            }
        }
    }

    // ----- Control flow -----
    try w.print("Control Flow:\n", .{});
    try w.print("- Conditional branches: {d}\n", .{cond_branches.items.len});
    try w.print("- Unconditional jumps: {d}\n", .{uncond_jumps.items.len});
    try w.print("- Loop back-edges (dest < src): {d}\n\n", .{loop_backedges.items.len});

    if (cond_branches.items.len != 0) {
        try w.print("Conditional branches:\n", .{});
        for (cond_branches.items) |e| {
            if (e.dst) |d| {
                try w.print("0x{x}: {s} -> 0x{x}\n", .{ e.src, e.mnemonic, d });
            } else {
                try w.print("0x{x}: {s} -> unknown\n", .{ e.src, e.mnemonic });
            }
        }
        try w.print("\n", .{});
    }

    if (uncond_jumps.items.len != 0) {
        try w.print("Unconditional jumps:\n", .{});
        for (uncond_jumps.items) |e| {
            if (e.dst) |d| {
                try w.print("0x{x}: {s} -> 0x{x}\n", .{ e.src, e.mnemonic, d });
            } else {
                try w.print("0x{x}: {s} -> unknown\n", .{ e.src, e.mnemonic });
            }
        }
        try w.print("\n", .{});
    }

    if (loop_backedges.items.len != 0) {
        try w.print("Loop candidates (back-edges):\n", .{});
        for (loop_backedges.items) |e| {
            if (e.dst) |d| {
                try w.print("0x{x}: {s} -> 0x{x}\n", .{ e.src, e.mnemonic, d });
            }
        }
        try w.print("\n", .{});
    }

    // ----- Memory behavior -----
    try w.print("Memory Behavior:\n", .{});
    try w.print("- Stack usage is best-effort from a linear scan (branches not followed).\n", .{});
    for (funcs.items, 0..) |f, fi| {
        if (f.name) |nm| {
            try w.print("Function: {s}\n", .{nm});
        } else {
            try w.print("Function at 0x{x} (unnamed)\n", .{f.start});
        }
        const min_delta = stack_min[fi];
        const reserved: u64 = if (min_delta < 0) @intCast(-min_delta) else 0;
        try w.print("- Max stack reserved (bytes): {d}\n", .{reserved});
        try w.print("- Minimum RSP delta (bytes): {d}\n", .{min_delta});
        try w.print("- Stack operations observed: {d}\n\n", .{stack_ops[fi]});
    }

    if (data == null) {
        try w.print(".data accesses: unknown (no .data section found)\n\n", .{});
    } else {
        const da = data.?;
        const DataCount = struct { count: usize, first_insn: u64 };
        var data_counts = std.AutoHashMap(u64, DataCount).init(alloc);
        defer data_counts.deinit();
        var data_keys = std.ArrayList(u64).init(alloc);
        defer data_keys.deinit();

        for (data_refs.items) |r| {
            const gop = try data_counts.getOrPut(r.target);
            if (!gop.found_existing) {
                gop.value_ptr.* = .{ .count = 1, .first_insn = r.insn_addr };
                try data_keys.append(r.target);
            } else {
                gop.value_ptr.count += 1;
                if (r.insn_addr < gop.value_ptr.first_insn) gop.value_ptr.first_insn = r.insn_addr;
            }
        }

        std.sort.heap(u64, data_keys.items, {}, std.sort.asc(u64));
        try w.print(".data accesses:\n", .{});
        try w.print("- Section range: 0x{x}..0x{x}\n", .{ da.addr, da.addr + da.bytes.len });
        try w.print("- Accessing instructions (RIP-relative): {d}\n", .{data_refs.items.len});
        try w.print("- Unique target addresses: {d}\n", .{data_keys.items.len});

        const max_show: usize = 32;
        const show_n: usize = @min(max_show, data_keys.items.len);
        if (data_keys.items.len != 0) {
            try w.print("- Targets (first {d}):\n", .{show_n});
            for (data_keys.items[0..show_n]) |addr| {
                const info = data_counts.get(addr).?;
                try w.print("  - 0x{x} (count {d}, first at 0x{x})\n", .{ addr, info.count, info.first_insn });
            }
            if (data_keys.items.len > max_show) {
                try w.print("  (showing first {d} of {d} targets)\n", .{ max_show, data_keys.items.len });
            }
        }
        try w.print("\n", .{});
    }

    // ----- Keywords -----
    try w.print("Keywords:\n", .{});
    try w.print("- Comparisons: cmp ({d}), test ({d})\n", .{ cmp_count, test_count });
    try w.print("- Loop candidates (back-edges): {d}\n", .{loop_backedges.items.len});

    // Syscall keywords
    var syscall_nums = std.AutoHashMap(u64, void).init(alloc);
    defer syscall_nums.deinit();
    var syscall_list = std.ArrayList(u64).init(alloc);
    defer syscall_list.deinit();
    var saw_unknown_syscall = false;
    for (syscalls.items) |sc| {
        if (sc.number) |n| {
            const gop = try syscall_nums.getOrPut(n);
            if (!gop.found_existing) try syscall_list.append(n);
        } else {
            saw_unknown_syscall = true;
        }
    }
    std.sort.heap(u64, syscall_list.items, {}, std.sort.asc(u64));
    if (syscall_list.items.len == 0 and !saw_unknown_syscall) {
        try w.print("- Syscalls: none (no direct `syscall` instruction detected)\n", .{});
    } else {
        try w.print("- Syscalls: ", .{});
        var first = true;
        for (syscall_list.items) |n| {
            if (!first) try w.print(", ", .{});
            first = false;
            const nm = syscallName(n) orelse "unknown";
            try w.print("{s}", .{nm});
        }
        if (saw_unknown_syscall) {
            if (!first) try w.print(", ", .{});
            try w.print("unknown", .{});
        }
        try w.print("\n", .{});
    }

    // Constant / magic values (immediates seen in instruction operands)
    std.sort.heap(i64, imm_list.items, {}, std.sort.asc(i64));
    const max_consts: usize = 32;
    const const_n: usize = @min(max_consts, imm_list.items.len);
    try w.print("- Constants (unique immediates): {d}\n", .{imm_list.items.len});
    if (const_n != 0) {
        try w.print("- Constants (first {d}): ", .{const_n});
        for (imm_list.items[0..const_n], 0..) |v, idx| {
            if (idx != 0) try w.print(", ", .{});
            if (v >= 0) {
                try w.print("0x{x}", .{@as(u64, @intCast(v))});
            } else {
                // Signed negative immediate
                try w.print("{d}", .{v});
            }
        }
        try w.print("\n", .{});
        if (imm_list.items.len > max_consts) {
            try w.print("  (showing first {d} of {d} constants)\n", .{ max_consts, imm_list.items.len });
        }
    }
    try w.print("\n", .{});

    try w.print("Behavior Summary:\n", .{});
    try w.print("- Deterministic rule-based analysis (no emulation).\n", .{});
    try w.print("- Functions: {d}, Syscalls: {d}, Strings: {d}\n", .{ funcs.items.len, syscalls.items.len, if (have_strings) strings.len else 0 });
}

const TextInst = struct {
    addr: ?u64,
    mnemonic: []const u8,
    ops: []const u8,
};

fn parseMaybeHexU64(s: []const u8) ?u64 {
    const t = std.mem.trim(u8, s, " \t");
    if (t.len == 0) return null;
    const no_dollar = if (t[0] == '$') t[1..] else t;
    if (no_dollar.len == 0) return null;

    if (std.mem.startsWith(u8, no_dollar, "0x") or std.mem.startsWith(u8, no_dollar, "0X")) {
        return std.fmt.parseInt(u64, no_dollar[2..], 16) catch null;
    }

    // Accept decimal digits.
    for (no_dollar) |ch| {
        if (ch < '0' or ch > '9') return null;
    }
    return std.fmt.parseInt(u64, no_dollar, 10) catch null;
}

fn renderSemanticsText(alloc: std.mem.Allocator, mnem: []const u8, ops: []const u8) ![]const u8 {
    // Mirror a subset of renderSemantics(), but based purely on text.
    if (std.mem.eql(u8, mnem, "sub") and (std.mem.startsWith(u8, ops, "rsp,") or std.mem.startsWith(u8, ops, "esp,"))) {
        return std.fmt.allocPrint(alloc, "The CPU adjusts the stack pointer downward to reserve stack space: {s}.", .{ops});
    }
    if (std.mem.eql(u8, mnem, "add") and (std.mem.startsWith(u8, ops, "rsp,") or std.mem.startsWith(u8, ops, "esp,"))) {
        return std.fmt.allocPrint(alloc, "The CPU adjusts the stack pointer upward to release stack space: {s}.", .{ops});
    }

    if (std.mem.eql(u8, mnem, "mov") or std.mem.eql(u8, mnem, "movabs")) {
        return std.fmt.allocPrint(alloc, "The CPU copies a value using mov: {s}.", .{ops});
    }
    if (std.mem.eql(u8, mnem, "lea")) {
        return std.fmt.allocPrint(alloc, "The CPU computes an effective address and writes it: {s}.", .{ops});
    }
    if (std.mem.eql(u8, mnem, "cmp")) {
        return std.fmt.allocPrint(alloc, "The CPU compares operands and updates flags without storing a result: {s}.", .{ops});
    }
    if (std.mem.eql(u8, mnem, "test")) {
        return std.fmt.allocPrint(alloc, "The CPU performs a bitwise test and updates flags without storing a result: {s}.", .{ops});
    }
    if (std.mem.eql(u8, mnem, "call")) {
        return std.fmt.allocPrint(alloc, "The CPU pushes a return address and transfers control to a call target: {s}.", .{ops});
    }
    if (std.mem.eql(u8, mnem, "ret")) {
        return std.fmt.allocPrint(alloc, "The CPU pops a return address and resumes execution at that address.", .{});
    }
    if (std.mem.eql(u8, mnem, "jmp")) {
        return std.fmt.allocPrint(alloc, "The CPU unconditionally transfers execution to: {s}.", .{ops});
    }
    if (mnem.len >= 1 and mnem[0] == 'j') {
        if (x86_64.jccCondition(mnem)) |cond| {
            return std.fmt.allocPrint(alloc, "The CPU checks condition flags ({s}) and conditionally transfers execution using {s}: {s}.", .{ cond, mnem, ops });
        }
        return std.fmt.allocPrint(alloc, "The CPU conditionally transfers execution based on flags using {s}: {s}.", .{ mnem, ops });
    }
    if (std.mem.eql(u8, mnem, "syscall")) {
        return std.fmt.allocPrint(alloc, "The CPU transitions to kernel mode to request an operating system service.", .{});
    }
    if (std.mem.eql(u8, mnem, "push")) {
        return std.fmt.allocPrint(alloc, "The CPU decrements the stack pointer and stores a value on the stack: {s}.", .{ops});
    }
    if (std.mem.eql(u8, mnem, "pop")) {
        return std.fmt.allocPrint(alloc, "The CPU loads a value from the stack and increments the stack pointer: {s}.", .{ops});
    }

    return std.fmt.allocPrint(alloc, "Unknown/unclear semantics for this instruction pattern: {s} {s}.", .{ mnem, ops });
}

fn analyzeAsmText(alloc: std.mem.Allocator, bytes: []const u8) !void {
    var insts = std.ArrayList(TextInst).init(alloc);
    defer insts.deinit();

    var it = std.mem.splitScalar(u8, bytes, '\n');
    while (it.next()) |raw_line| {
        var line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) continue;

        // Remove comments.
        if (std.mem.indexOfScalar(u8, line, ';')) |idx| line = std.mem.trimRight(u8, line[0..idx], " \t");
        if (std.mem.indexOfScalar(u8, line, '#')) |idx| line = std.mem.trimRight(u8, line[0..idx], " \t");
        if (line.len == 0) continue;

        // Ignore labels.
        if (line[line.len - 1] == ':' and std.mem.indexOfAny(u8, line, " \t") == null) continue;

        var addr: ?u64 = null;
        if (std.mem.indexOfScalar(u8, line, ':')) |colon| {
            const left = std.mem.trim(u8, line[0..colon], " \t");
            if (parseMaybeHexU64(left)) |v| {
                addr = v;
                line = std.mem.trimLeft(u8, line[colon + 1 ..], " \t");
            }
        }

        // mnemonic + rest
        const sp = std.mem.indexOfAny(u8, line, " \t") orelse line.len;
        const mnemonic = line[0..sp];
        const rest = if (sp < line.len) std.mem.trimLeft(u8, line[sp..], " \t") else "";
        if (mnemonic.len == 0) continue;

        try insts.append(.{ .addr = addr, .mnemonic = mnemonic, .ops = rest });
    }

    var per_cat: [6]usize = .{0} ** 6;
    for (insts.items) |ti| {
        const cat = classify(ti.mnemonic, ti.ops);
        per_cat[@intFromEnum(cat)] += 1;
    }

    const w = std.io.getStdOut().writer();
    try w.print("Architecture: x86-64\n\n", .{});

    try w.print("Instruction Overview:\n", .{});
    try w.print("- Total instructions: {d}\n", .{insts.items.len});
    var cati: usize = 0;
    while (cati < per_cat.len) : (cati += 1) {
        const cat: Category = @enumFromInt(cati);
        try w.print("- {s}: {d}\n", .{ categoryName(cat), per_cat[cati] });
    }
    try w.print("\nCategory meanings:\n", .{});
    try w.print("- data movement: The CPU transfers values or addresses between registers and memory.\n", .{});
    try w.print("- arithmetic / logic: The CPU performs calculations/bit-ops and updates flags.\n", .{});
    try w.print("- control flow: The CPU changes the instruction pointer (jumps, calls, returns).\n", .{});
    try w.print("- stack manipulation: The CPU changes RSP or uses the stack for storage/calls.\n", .{});
    try w.print("- system boundary: The CPU crosses into the kernel or privileged boundary (e.g. syscall).\n", .{});
    try w.print("- other: Instructions not yet categorized.\n\n", .{});

    try w.print("Functions:\n", .{});
    try w.print("Functions detected: 0\n\n", .{});

    // Syscall detection based on textual RAX/EAX tracking.
    var syscalls = std.ArrayList(SyscallEvent).init(alloc);
    defer syscalls.deinit();
    var last_rax_imm: ?u64 = null;

    // Control-flow edges.
    var cond_branches = std.ArrayList(BranchEdge).init(alloc);
    defer cond_branches.deinit();
    var uncond_jumps = std.ArrayList(BranchEdge).init(alloc);
    defer uncond_jumps.deinit();

    var loop_backedges: usize = 0;
    var cmp_count: usize = 0;
    var test_count: usize = 0;

    var stack_cur: i64 = 0;
    var stack_min: i64 = 0;
    var stack_ops: usize = 0;

    var const_seen = std.AutoHashMap(u64, void).init(alloc);
    defer const_seen.deinit();
    var const_list = std.ArrayList(u64).init(alloc);
    defer const_list.deinit();

    try w.print("CPU Semantics:\n", .{});
    for (insts.items) |ti| {
        if (std.mem.eql(u8, ti.mnemonic, "cmp")) cmp_count += 1;
        if (std.mem.eql(u8, ti.mnemonic, "test")) test_count += 1;

        // Best-effort constant extraction from operand text.
        var tok = std.mem.tokenizeAny(u8, ti.ops, " \t,[]()+");
        while (tok.next()) |t| {
            if (parseMaybeHexU64(t)) |v| {
                const gop = const_seen.getOrPut(v) catch continue;
                if (!gop.found_existing) const_list.append(v) catch {};
            }
        }

        // Stack tracking (linear best-effort).
        if (std.mem.eql(u8, ti.mnemonic, "push")) {
            stack_cur -= 8;
            if (stack_cur < stack_min) stack_min = stack_cur;
            stack_ops += 1;
        } else if (std.mem.eql(u8, ti.mnemonic, "pop")) {
            stack_cur += 8;
            stack_ops += 1;
        } else if ((std.mem.eql(u8, ti.mnemonic, "sub") or std.mem.eql(u8, ti.mnemonic, "add")) and std.mem.startsWith(u8, ti.ops, "rsp,")) {
            const rhs = std.mem.trimLeft(u8, ti.ops[4..], " \t");
            if (parseMaybeHexU64(rhs)) |imm| {
                const delta: i64 = @intCast(imm);
                if (std.mem.eql(u8, ti.mnemonic, "sub")) {
                    stack_cur -= delta;
                    if (stack_cur < stack_min) stack_min = stack_cur;
                } else {
                    stack_cur += delta;
                }
                stack_ops += 1;
            }
        }

        // Update RAX tracking (very conservative, text-only).
        if (std.mem.eql(u8, ti.mnemonic, "mov") or std.mem.eql(u8, ti.mnemonic, "movabs")) {
            if (std.mem.startsWith(u8, ti.ops, "rax,") or std.mem.startsWith(u8, ti.ops, "eax,")) {
                const rhs = std.mem.trimLeft(u8, ti.ops[4..], " \t");
                last_rax_imm = parseMaybeHexU64(rhs);
            }
        } else if (std.mem.eql(u8, ti.mnemonic, "xor")) {
            if (std.mem.startsWith(u8, ti.ops, "eax, eax") or std.mem.startsWith(u8, ti.ops, "rax, rax")) {
                last_rax_imm = 0;
            }
        }

        if (std.mem.eql(u8, ti.mnemonic, "syscall")) {
            try syscalls.append(.{ .addr = ti.addr orelse 0, .number = last_rax_imm });
        }

        if (std.mem.eql(u8, ti.mnemonic, "jmp") or (ti.mnemonic.len >= 1 and ti.mnemonic[0] == 'j')) {
            const maybe_dst = parseMaybeHexU64(std.mem.trim(u8, ti.ops, " \t"));
            const src = ti.addr orelse 0;
            const edge: BranchEdge = .{ .src = src, .dst = maybe_dst, .mnemonic = ti.mnemonic };
            if (std.mem.eql(u8, ti.mnemonic, "jmp")) {
                try uncond_jumps.append(edge);
            } else {
                try cond_branches.append(edge);
            }
            if (maybe_dst) |d| {
                if (src != 0 and d < src) loop_backedges += 1;
            }
        }

        const sem = try renderSemanticsText(alloc, ti.mnemonic, ti.ops);
        defer alloc.free(sem);

        if (ti.addr) |a| {
            try w.print("0x{x}: {s} {s}\n", .{ a, ti.mnemonic, ti.ops });
        } else {
            try w.print("unknown: {s} {s}\n", .{ ti.mnemonic, ti.ops });
        }
        try w.print("- Category: {s}\n", .{categoryName(classify(ti.mnemonic, ti.ops))});
        try w.print("- Explanation: {s}\n\n", .{sem});
    }

    try w.print("Syscalls:\n", .{});
    if (syscalls.items.len == 0) {
        try w.print("(none detected)\n\n", .{});
    } else {
        for (syscalls.items) |sc| {
            if (sc.number) |n| {
                const nm = syscallName(n) orelse "unknown";
                try w.print("Syscall: {s}\n", .{nm});
                if (sc.addr != 0) try w.print("- Address: 0x{x}\n", .{sc.addr}) else try w.print("- Address: unknown\n", .{});
                try w.print("- Number: {d}\n", .{n});
                try w.print("- Registers: {s}\n", .{syscallArgsDesc(nm)});
                try w.print("- Description: {s}\n\n", .{syscallDesc(nm)});
            } else {
                try w.print("Syscall: unknown\n", .{});
                if (sc.addr != 0) try w.print("- Address: 0x{x}\n", .{sc.addr}) else try w.print("- Address: unknown\n", .{});
                try w.print("- Number: unknown\n", .{});
                try w.print("- Registers: rdi, rsi, rdx, r10, r8, r9 (calling convention)\n", .{});
                try w.print("- Description: The CPU transitions to kernel mode to request an operating system service.\n\n", .{});
            }
        }
    }

    try w.print("System Interaction:\n", .{});
    if (syscalls.items.len == 0) {
        try w.print("- No direct system call instructions were detected in this assembly text.\n", .{});
        try w.print("- Any operating system interaction would occur outside this listing (for example, through a caller or through library code), not via `syscall` shown here.\n", .{});
        try w.print("- At the CPU level, this is about ordinary `call` and `ret` control transfers, not explicit kernel transitions.\n\n", .{});
    } else {
        try w.print("- Direct system call instructions were detected in this assembly text.\n", .{});
        try w.print("- Each `syscall` represents a CPU-level transition into the kernel boundary.\n\n", .{});
    }

    try w.print("Strings:\n", .{});
    try w.print("(not available for assembly-text input)\n\n", .{});

    try w.print("Control Flow:\n", .{});
    try w.print("- Conditional branches: {d}\n", .{cond_branches.items.len});
    try w.print("- Unconditional jumps: {d}\n", .{uncond_jumps.items.len});
    try w.print("- Loop back-edges (dest < src): {d}\n\n", .{loop_backedges});

    if (cond_branches.items.len != 0) {
        try w.print("Conditional branches:\n", .{});
        for (cond_branches.items) |e| {
            if (e.dst) |d| {
                if (e.src != 0) try w.print("0x{x}: {s} -> 0x{x}\n", .{ e.src, e.mnemonic, d }) else try w.print("unknown: {s} -> 0x{x}\n", .{ e.mnemonic, d });
            } else {
                if (e.src != 0) try w.print("0x{x}: {s} -> unknown\n", .{ e.src, e.mnemonic }) else try w.print("unknown: {s} -> unknown\n", .{e.mnemonic});
            }
        }
        try w.print("\n", .{});
    }

    if (uncond_jumps.items.len != 0) {
        try w.print("Unconditional jumps:\n", .{});
        for (uncond_jumps.items) |e| {
            if (e.dst) |d| {
                if (e.src != 0) try w.print("0x{x}: {s} -> 0x{x}\n", .{ e.src, e.mnemonic, d }) else try w.print("unknown: {s} -> 0x{x}\n", .{ e.mnemonic, d });
            } else {
                if (e.src != 0) try w.print("0x{x}: {s} -> unknown\n", .{ e.src, e.mnemonic }) else try w.print("unknown: {s} -> unknown\n", .{e.mnemonic});
            }
        }
        try w.print("\n", .{});
    }

    // ----- Memory behavior -----
    try w.print("Memory Behavior:\n", .{});
    try w.print("- Stack usage is best-effort from a linear scan (branches not followed).\n", .{});
    const reserved: u64 = if (stack_min < 0) @intCast(-stack_min) else 0;
    try w.print("- Max stack reserved (bytes): {d}\n", .{reserved});
    try w.print("- Minimum RSP delta (bytes): {d}\n", .{stack_min});
    try w.print("- Stack operations observed: {d}\n\n", .{stack_ops});

    // ----- Keywords -----
    try w.print("Keywords:\n", .{});
    try w.print("- Comparisons: cmp ({d}), test ({d})\n", .{ cmp_count, test_count });

    // Syscall keywords
    var syscall_nums = std.AutoHashMap(u64, void).init(alloc);
    defer syscall_nums.deinit();
    var syscall_list = std.ArrayList(u64).init(alloc);
    defer syscall_list.deinit();
    var saw_unknown_syscall = false;
    for (syscalls.items) |sc| {
        if (sc.number) |n| {
            const gop = syscall_nums.getOrPut(n) catch continue;
            if (!gop.found_existing) syscall_list.append(n) catch {};
        } else {
            saw_unknown_syscall = true;
        }
    }
    std.sort.heap(u64, syscall_list.items, {}, std.sort.asc(u64));
    if (syscall_list.items.len == 0 and !saw_unknown_syscall) {
        try w.print("- Syscalls: none (no direct `syscall` instruction detected)\n", .{});
    } else {
        try w.print("- Syscalls: ", .{});
        var first = true;
        for (syscall_list.items) |n| {
            if (!first) try w.print(", ", .{});
            first = false;
            const nm = syscallName(n) orelse "unknown";
            try w.print("{s}", .{nm});
        }
        if (saw_unknown_syscall) {
            if (!first) try w.print(", ", .{});
            try w.print("unknown", .{});
        }
        try w.print("\n", .{});
    }

    std.sort.heap(u64, const_list.items, {}, std.sort.asc(u64));
    const max_consts: usize = 32;
    const const_n: usize = @min(max_consts, const_list.items.len);
    try w.print("- Constants (unique immediates): {d}\n", .{const_list.items.len});
    if (const_n != 0) {
        try w.print("- Constants (first {d}): ", .{const_n});
        for (const_list.items[0..const_n], 0..) |v, idx| {
            if (idx != 0) try w.print(", ", .{});
            try w.print("0x{x}", .{v});
        }
        try w.print("\n", .{});
        if (const_list.items.len > max_consts) {
            try w.print("  (showing first {d} of {d} constants)\n", .{ max_consts, const_list.items.len });
        }
    }
    try w.print("\n", .{});

    try w.print("Behavior Summary:\n", .{});
    try w.print("- Deterministic rule-based analysis of assembly text (no disassembly, no emulation).\n", .{});
}

fn isElf(bytes: []const u8) bool {
    return bytes.len >= 4 and bytes[0] == 0x7f and bytes[1] == 'E' and bytes[2] == 'L' and bytes[3] == 'F';
}

fn run() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    // Spec says no flags; accept exactly one argument.
    if (args.len != 2) {
        // Deterministic, no help text.
        return error.InvalidArguments;
    }

    const path = args[1];
    const file_bytes = try std.fs.cwd().readFileAlloc(alloc, path, 1024 * 1024 * 128);
    defer alloc.free(file_bytes);

    if (isElf(file_bytes)) {
        const parsed = try Elf.parse(alloc, file_bytes);
        defer {
            for (parsed.funcs) |f| alloc.free(f.name);
            alloc.free(parsed.funcs);
        }

        const text = parsed.text orelse return error.MissingText;
        disassembleAndPrint(alloc, text.addr, text.bytes, parsed.rodata, parsed.data, parsed.funcs, parsed.entry) catch |err| {
            if (err == error.BrokenPipe) return;
            return err;
        };
        return;
    }

    // Assembly-text mode.
    analyzeAsmText(alloc, file_bytes) catch |err| {
        if (err == error.BrokenPipe) return;
        return err;
    };
}

pub fn entry() void {
    run() catch |err| {
        if (err == error.BrokenPipe) return;
        // Print deterministic error to stdout (no help/usage text).
        const w = std.io.getStdOut().writer();
        w.print("Error: {s}\n", .{@errorName(err)}) catch {};
        std.process.exit(1);
    };
}
