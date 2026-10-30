const std = @import("std");

const max_file = 256 * 1024 * 1024;

const ORIGINAL_SHA256 = "bf3183ab330c2185b01940f3841b39c2eefd279cff2872d3e03d37853797b781";

const StatusSite = struct {
    sig: []const u8,
    patched: []const u8,
};

const status_sites = [_]StatusSite{
    .{ .sig = &[_]u8{ 0x41, 0x80, 0x38, 0x00, 0x75, 0x4c }, .patched = &[_]u8{ 0x41, 0xC6, 0x00, 0x00, 0x90, 0x90 } },
    .{ .sig = &[_]u8{ 0x41, 0x80, 0x38, 0x00, 0x75, 0x3f }, .patched = &[_]u8{ 0x41, 0xC6, 0x00, 0x00, 0x90, 0x90 } },
};

const Guard = enum { license_combo, trial_plan, dialog_param, string_copy, plan_type, plan_type_r14 };

const GuardSite = struct {
    sig: []const u8,
    len: usize,
    resume_at: usize,
    guard: Guard,
};

const guard_sites = [_]GuardSite{

    .{ .sig = &[_]u8{ 0x49, 0x8b, 0x47, 0x30, 0x48, 0x8b, 0xb0, 0x28, 0x02, 0x00, 0x00 }, .len = 11, .resume_at = 11, .guard = .license_combo },

    .{ .sig = &[_]u8{ 0x48, 0x8b, 0x8b, 0x28, 0x02, 0x00, 0x00, 0x80, 0x79, 0x50, 0x01 }, .len = 11, .resume_at = 11, .guard = .trial_plan },

    .{ .sig = &[_]u8{ 0x4c, 0x8b, 0xc8, 0x4c, 0x8b, 0x87, 0xd8, 0x00, 0x00, 0x00 }, .len = 10, .resume_at = 10, .guard = .dialog_param },

    .{ .sig = &[_]u8{ 0x48, 0x83, 0x7a, 0x18, 0x10, 0x48, 0x8b, 0x6a, 0x10, 0x72, 0x03 }, .len = 5, .resume_at = 5, .guard = .string_copy },

    .{ .sig = &[_]u8{ 0x48, 0x8b, 0x83, 0x28, 0x02, 0x00, 0x00, 0x0f, 0xb6, 0x58, 0x50 }, .len = 7, .resume_at = 7, .guard = .plan_type },

    .{ .sig = &[_]u8{ 0x4c, 0x8b, 0xb2, 0x28, 0x02, 0x00, 0x00, 0x66, 0x0f, 0x6f, 0x05 }, .len = 7, .resume_at = 7, .guard = .plan_type_r14 },
};

const STATUS_1_SIG_OFF = 0;

const Section = struct {
    name: [8]u8,
    virtual_size: u32,
    virtual_address: u32,
    raw_size: u32,
    raw_ptr: u32,
    characteristics: u32,

    fn isText(self: Section) bool {
        return std.mem.eql(u8, std.mem.sliceTo(&self.name, 0), ".text");
    }
    fn isData(self: Section) bool {
        return std.mem.eql(u8, std.mem.sliceTo(&self.name, 0), ".data");
    }
    fn writable(self: Section) bool {
        return (self.characteristics & 0x8000_0000) != 0;
    }
};

const Image = struct {
    data: []u8,
    image_base: u64,
    checksum_off: usize,
    sections: []Section,

    fn rvaToOff(self: *Image, rva: u32) !usize {
        for (self.sections) |s| {
            if (rva >= s.virtual_address and rva < s.virtual_address + s.raw_size) {
                return @as(usize, s.raw_ptr) + (rva - s.virtual_address);
            }
        }
        return error.RvaOutOfRange;
    }

    fn sectionAt(self: *Image, off: usize) ?*Section {
        for (self.sections) |*s| {
            if (off >= s.raw_ptr and off < @as(usize, s.raw_ptr) + s.raw_size) return s;
        }
        return null;
    }
};

const stub_size = 0xD0;

const StubBuilder = struct {
    buf: [stub_size]u8 = undefined,
    len: usize = 0,
    base_va: u64 = 0,
    fixes: [8]struct { pos: usize, target: u64 } = undefined,
    nfix: usize = 0,

    fn emit(self: *StubBuilder, bytes: []const u8) void {
        @memcpy(self.buf[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    fn rel32(self: *StubBuilder, target_va: u64) void {
        self.fixes[self.nfix] = .{ .pos = self.len, .target = target_va };
        self.nfix += 1;
        self.emit(&[_]u8{ 0, 0, 0, 0 });
    }

    fn leaRip(self: *StubBuilder, prefix: []const u8, target_va: u64) void {
        self.emit(prefix);
        self.rel32(target_va);
    }

    fn resolve(self: *StubBuilder) void {
        for (self.fixes[0..self.nfix]) |f| {
            const next = self.base_va + f.pos + 4;
            const disp: i64 = @as(i64, @intCast(f.target)) - @as(i64, @intCast(next));
            std.mem.writeInt(i32, self.buf[f.pos..][0..4], @intCast(disp), .little);
        }
    }
};

fn sigsEqual(data: []const u8, off: usize, bytes: []const u8) bool {
    if (off + bytes.len > data.len) return false;
    return std.mem.eql(u8, data[off..][0..bytes.len], bytes);
}

fn findUnique(data: []const u8, sig: []const u8) !usize {
    var found: ?usize = null;
    var i: usize = 0;
    while (i + sig.len <= data.len) : (i += 1) {
        if (std.mem.eql(u8, data[i..][0..sig.len], sig)) {
            if (found != null) return error.SignatureNotUnique;
            found = i;
        }
    }
    return found orelse error.SignatureMissing;
}

fn findZeros(data: []const u8, start: usize, end: usize, len: usize) !usize {
    if (end > data.len or end <= start) return error.RvaOutOfRange;
    var run: usize = 0;
    var i = start;
    while (i < end) : (i += 1) {
        if (data[i] == 0) {
            run += 1;
            if (run >= len) return i + 1 - len;
        } else run = 0;
    }
    return error.NoCodeCave;
}

fn parseImage(data: []u8, allocator: std.mem.Allocator) !Image {
    if (data.len < 0x200) return error.NotAnImage;
    if (!std.mem.eql(u8, data[0..2], "MZ")) return error.NotAnImage;
    const e_lfanew = std.mem.readInt(u32, data[0x3c..][0..4], .little);
    if (std.mem.eql(u8, data[e_lfanew..][0..4], "PE\x00\x00") == false) return error.NotAnImage;
    const machine = std.mem.readInt(u16, data[e_lfanew + 4 ..][0..2], .little);
    if (machine != 0x8664) return error.NotX64;
    const nsec = std.mem.readInt(u16, data[e_lfanew + 6 ..][0..2], .little);
    const opt_size = std.mem.readInt(u16, data[e_lfanew + 20 ..][0..2], .little);
    const opt = e_lfanew + 24;
    if (std.mem.readInt(u16, data[opt..][0..2], .little) != 0x20b) return error.NotPe32Plus;
    const image_base = std.mem.readInt(u64, data[opt + 24 ..][0..8], .little);
    const secs = try allocator.alloc(Section, nsec);
    var i: usize = 0;
    while (i < nsec) : (i += 1) {
        const h = opt + opt_size + i * 40;
        var s: Section = undefined;
        @memcpy(&s.name, data[h..][0..8]);
        s.virtual_size = std.mem.readInt(u32, data[h + 8 ..][0..4], .little);
        s.virtual_address = std.mem.readInt(u32, data[h + 12 ..][0..4], .little);
        s.raw_size = std.mem.readInt(u32, data[h + 16 ..][0..4], .little);
        s.raw_ptr = std.mem.readInt(u32, data[h + 20 ..][0..4], .little);
        s.characteristics = std.mem.readInt(u32, data[h + 36 ..][0..4], .little);
        secs[i] = s;
    }
    return .{ .data = data, .image_base = image_base, .checksum_off = opt + 64, .sections = secs };
}

fn peChecksum(img: *Image) u32 {
    var sum: u32 = 0;
    const d = img.data;
    var i: usize = 0;
    while (i + 1 < d.len) : (i += 2) {
        if (i == img.checksum_off or i + 1 == img.checksum_off) continue;
        sum +%= std.mem.readInt(u16, d[i..][0..2], .little);
        sum = (sum & 0xffff) + (sum >> 16);
    }
    if (d.len & 1 != 0) sum +%= d[d.len - 1];
    sum = (sum & 0xffff) + (sum >> 16);
    return sum +% @as(u32, @intCast(d.len));
}

fn buildStatusPatch(img: *Image) !usize {
    var count: usize = 0;
    for (status_sites) |s| {
        const off = try findUnique(img.data, s.sig);
        if (sigsEqual(img.data, off, s.patched)) continue;
        @memcpy(img.data[off..][0..s.patched.len], s.patched);
        count += 1;
    }
    return count;
}

fn alignUp(v: usize, a: usize) usize {
    return (v + a - 1) & ~(a - 1);
}

fn emitDummyHelper(b: *StubBuilder, dummy_va: u64, _: u64) void {
    b.emit(&[_]u8{ 0x48, 0x8d, 0x05 });
    b.rel32(dummy_va);
    b.emit(&[_]u8{0xC3});
}

fn buildGuards(img: *Image, allocator: std.mem.Allocator) !usize {
    var offs: [guard_sites.len]usize = undefined;
    for (guard_sites, 0..) |g, i| offs[i] = try findUnique(img.data, g.sig);

    var text: ?*Section = null;
    for (img.sections) |*s| if (s.isText()) {
        text = s;
    };
    if (text == null) return error.NoTextSection;

    const slot_va_dummy: u64 = 0;
    _ = slot_va_dummy;

    var last: *Section = &img.sections[0];
    for (img.sections) |*s| {
        if (@as(usize, s.virtual_address) + s.virtual_size > @as(usize, last.virtual_address) + last.virtual_size) last = s;
    }
    const sec_size: usize = 0x1000;
    const new_rva = alignUp(@as(usize, last.virtual_address) + last.virtual_size, 0x1000);
    const new_va = img.image_base + new_rva;
    const raw_off = alignUp(img.data.len, 0x200);
    const e_lfanew = std.mem.readInt(u32, img.data[0x3c..][0..4], .little);
    const nsec = std.mem.readInt(u16, img.data[e_lfanew + 6 ..][0..2], .little);
    const opt_size = std.mem.readInt(u16, img.data[e_lfanew + 20 ..][0..2], .little);
    const hdr_off = e_lfanew + 24 + @as(usize, opt_size) + @as(usize, nsec) * 40;
    if (hdr_off + 40 > 0x400) return error.NoHeaderSpace;

    const need = raw_off + sec_size;
    const out = try allocator.alloc(u8, need);
    @memset(out, 0);
    @memcpy(out[0..img.data.len], img.data);
    allocator.free(img.data);
    img.data = out;

    var hdr = [_]u8{0} ** 40;
    @memcpy(hdr[0..6], ".patch");
    std.mem.writeInt(u32, hdr[8..12], @intCast(sec_size), .little);
    std.mem.writeInt(u32, hdr[12..16], @intCast(new_rva), .little);
    std.mem.writeInt(u32, hdr[16..20], @intCast(sec_size), .little);
    std.mem.writeInt(u32, hdr[20..24], @intCast(raw_off), .little);
    std.mem.writeInt(u32, hdr[36..40], 0xE0000020, .little);
    @memcpy(img.data[hdr_off..][0..40], &hdr);
    std.mem.writeInt(u16, img.data[e_lfanew + 6 ..][0..2], nsec + 1, .little);
    const opt = e_lfanew + 24;
    std.mem.writeInt(u32, img.data[opt + 56 ..][0..4], @intCast(alignUp(new_rva + sec_size, 0x1000)), .little);

    const slot_va = new_va;
    var used: usize = 0x400;
    {
        var b = StubBuilder{ .base_va = new_va + used };
        emitDummyHelper(&b, slot_va, 0x14055bfe8);
        b.resolve();
        @memcpy(img.data[raw_off + used ..][0..b.len], b.buf[0..b.len]);
        used += b.len;
    }

    for (guard_sites, 0..) |g, i| {
        const site_off = offs[i];
        const resume_va = img.image_base + rvaOf(img, site_off) + g.resume_at;
        var b = StubBuilder{ .base_va = new_va + used };
        switch (g.guard) {
            .license_combo => {
                const epilogue_va = try findEpilogue(img, site_off);
                b.emit(&[_]u8{ 0x49, 0x8b, 0x47, 0x30 });
                b.emit(&[_]u8{ 0x48, 0x85, 0xc0 });
                b.emit(&[_]u8{ 0x0F, 0x84 });
                b.rel32(epilogue_va);
                b.emit(&[_]u8{ 0x48, 0x8b, 0xb0, 0x28, 0x02, 0x00, 0x00 });
                b.emit(&[_]u8{ 0x48, 0x85, 0xf6 });
                b.emit(&[_]u8{ 0x0F, 0x85 });
                b.rel32(resume_va);
                b.emit(&[_]u8{0xE8});
                b.rel32(new_va);
                b.emit(&[_]u8{ 0x48, 0x89, 0xc6 });
                b.emit(&[_]u8{0xE9});
                b.rel32(resume_va);
            },
            .trial_plan => {
                b.emit(&[_]u8{ 0x48, 0x8b, 0x8b, 0x28, 0x02, 0x00, 0x00 });
                b.emit(&[_]u8{ 0x48, 0x85, 0xc9 });
                b.emit(&[_]u8{0x75, 0x00});
                b.buf[b.len - 1] = 8;
                b.emit(&[_]u8{0xE8});
                b.rel32(new_va);
                b.emit(&[_]u8{ 0x48, 0x89, 0xc1 });
                b.emit(&[_]u8{ 0x80, 0x79, 0x50, 0x01 });
                b.emit(&[_]u8{0xE9});
                b.rel32(resume_va);
            },
            .dialog_param => {
                b.emit(&[_]u8{ 0x4c, 0x8b, 0xc8 });
                b.emit(&[_]u8{ 0x48, 0x85, 0xc0 });
                b.emit(&[_]u8{0x75, 0x00});
                b.buf[b.len - 1] = 15;
                b.emit(&[_]u8{0xE8});
                b.rel32(new_va);
                b.emit(&[_]u8{ 0x49, 0x89, 0xc1 });
                b.emit(&[_]u8{ 0x4c, 0x8b, 0x87, 0xd8, 0x00, 0x00, 0x00 });
                b.emit(&[_]u8{0xE9});
                b.rel32(resume_va);
            },
            .string_copy => {
                b.emit(&[_]u8{ 0x48, 0x81, 0xfa, 0x00, 0x10, 0x00, 0x00 });
                b.emit(&[_]u8{0x73, 0x00});
                b.buf[b.len - 1] = 11;
                b.emit(&[_]u8{0xE8});
                b.rel32(new_va);
                b.emit(&[_]u8{ 0x48, 0x89, 0xc2 });
                b.emit(&[_]u8{ 0x48, 0x8b, 0xfa });
                b.emit(&[_]u8{ 0x48, 0x83, 0x7a, 0x18, 0x10 });
                b.emit(&[_]u8{0xE9});
                b.rel32(resume_va);
            },
            .plan_type => {
                b.emit(&[_]u8{ 0x48, 0x8b, 0x83, 0x28, 0x02, 0x00, 0x00 });
                b.emit(&[_]u8{ 0x48, 0x85, 0xc0 });
                b.emit(&[_]u8{0x75, 0x00});
                b.buf[b.len - 1] = 8;
                b.emit(&[_]u8{0xE8});
                b.rel32(new_va);
                b.emit(&[_]u8{ 0x48, 0x89, 0xc0 });
                b.emit(&[_]u8{0xE9});
                b.rel32(resume_va);
            },
            .plan_type_r14 => {
                const epi = try findEpilogue(img, site_off);
                b.emit(&[_]u8{ 0x4c, 0x8b, 0xb2, 0x28, 0x02, 0x00, 0x00 });
                b.emit(&[_]u8{ 0x4d, 0x85, 0xf6 });
                b.emit(&[_]u8{ 0x0F, 0x85 });
                b.rel32(resume_va);
                b.emit(&[_]u8{0xE9});
                b.rel32(epi);
            },
        }
        b.resolve();
        if (used + b.len > sec_size) return error.NoCodeCave;
        @memcpy(img.data[raw_off + used ..][0..b.len], b.buf[0..b.len]);
        const stub_va = new_va + used;
        used += b.len;

        const disp: i64 = @as(i64, @intCast(stub_va)) - @as(i64, @intCast(img.image_base + rvaOf(img, site_off) + 5));
        img.data[site_off] = 0xE9;
        std.mem.writeInt(i32, img.data[site_off + 1 ..][0..4], @intCast(disp), .little);
        var k: usize = 5;
        while (k < g.len) : (k += 1) img.data[site_off + k] = 0x90;
    }
    return guard_sites.len;
}

fn findEpilogue(img: *Image, from: usize) !u64 {

    const lea_pat = [_]u8{ 0x4c, 0x8d, 0x9c, 0x24 };
    const tail = [_]u8{ 0x41, 0x5f, 0x41, 0x5e, 0x5d, 0xc3 };
    var i = from;
    while (i + lea_pat.len + tail.len + 40 < img.data.len) : (i += 1) {
        if (!std.mem.eql(u8, img.data[i..][0..lea_pat.len], &lea_pat)) continue;
        var j = i + lea_pat.len;
        const stop = @min(j + 40, img.data.len - tail.len);
        while (j < stop) : (j += 1) {
            if (!std.mem.eql(u8, img.data[j..][0..tail.len], &tail)) continue;
            if (j + tail.len > stop + tail.len) break;
            return img.image_base + rvaOf(img, i);
        }
    }
    return error.NoEpilogueFound;
}

fn rvaOf(img: *Image, off: usize) u64 {
    const s = img.sectionAt(off).?;
    return @as(u64, s.virtual_address) + (off - s.raw_ptr);
}

fn defaultPath(allocator: std.mem.Allocator, io: std.Io) ![]u8 {
    const candidates = [_][]const u8{
        "C:\\Program Files\\Superluminal\\Performance\\Profiler.exe",
        "C:\\Program Files (x86)\\Superluminal\\Performance\\Profiler.exe",
    };
    for (candidates) |c| {
        std.Io.Dir.cwd().access(io, c, .{}) catch continue;
        return allocator.dupe(u8, c);
    }
    return error.ProfilerNotFound;
}

fn sha256Hex(data: []const u8, out: *[64]u8) void {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    const hexchars = "0123456789abcdef";
    for (digest, 0..) |b, i| {
        out[i * 2] = hexchars[b >> 4];
        out[i * 2 + 1] = hexchars[b & 0xf];
    }
}

fn countOccurrences(data: []const u8, needle: []const u8) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i + needle.len <= data.len) : (i += 1) {
        if (std.mem.eql(u8, data[i..][0..needle.len], needle)) n += 1;
    }
    return n;
}

const State = enum { original, patched, unknown };

const patched_status_bytes = [_]u8{ 0x41, 0xC6, 0x00, 0x00, 0x90, 0x90 };

fn detectState(img: *Image) State {
    var orig: usize = 0;
    for (status_sites) |st| {
        if (findUnique(img.data, st.sig)) |_| orig += 1 else |_| {}
    }
    if (orig == status_sites.len) return .original;
    if (countOccurrences(img.data, &patched_status_bytes) >= status_sites.len) return .patched;
    return .unknown;
}

fn usage() void {
    std.debug.print(
        \\slpatch - Superluminal Performance license-check patcher
        \\
        \\  slpatch [--path <Profiler.exe>] [--dry-run]
        \\  slpatch --status  [--path <Profiler.exe>]
        \\  slpatch --restore [--path <Profiler.exe>]
        \\
        \\Without --path the installed binary under %ProgramFiles% is used.
        \\An elevated shell is required to write into Program Files.
        \\
    , .{});
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var it = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer it.deinit();
    _ = it.next();

    var path_arg: ?[]const u8 = null;
    defer if (path_arg) |p| allocator.free(p);
    var dry_run = false;
    var want_status = false;
    var want_restore = false;

    while (it.next()) |a| {
        if (std.mem.eql(u8, a, "--path")) {
            const v = it.next() orelse {
                usage();
                std.process.exit(1);
            };
            path_arg = try allocator.dupe(u8, v);
        } else if (std.mem.eql(u8, a, "--dry-run")) {
            dry_run = true;
        } else if (std.mem.eql(u8, a, "--status")) {
            want_status = true;
        } else if (std.mem.eql(u8, a, "--restore")) {
            want_restore = true;
        } else if (std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help")) {
            return usage();
        } else {
            std.debug.print("unknown argument: {s}\n", .{a});
            return usage();
        }
    }

    const path = if (path_arg) |p| try allocator.dupe(u8, p) else defaultPath(allocator, io) catch {
        std.debug.print("Profiler.exe not found, pass --path\n", .{});
        std.process.exit(2);
    };
    defer allocator.free(path);
    std.debug.print("target: {s}\n", .{path});

    const backup = try std.fmt.allocPrint(allocator, "{s}.orig", .{path});
    defer allocator.free(backup);
    const dir = std.Io.Dir.cwd();

    if (want_restore) {
        const data = dir.readFileAlloc(io, backup, allocator, std.Io.Limit.limited(max_file)) catch |e| {
            std.debug.print("no usable backup at {s} ({s})\n", .{ backup, @errorName(e) });
            std.process.exit(2);
        };
        defer allocator.free(data);
        dir.writeFile(io, .{ .sub_path = path, .data = data }) catch |e| {
            std.debug.print("restore failed: {s} (elevated shell?)\n", .{@errorName(e)});
            std.process.exit(2);
        };
        std.debug.print("restored stock binary from backup\n", .{});
        return;
    }

    const data = dir.readFileAlloc(io, path, allocator, std.Io.Limit.limited(max_file)) catch |e| {
        std.debug.print("cannot read {s}: {s}\n", .{ path, @errorName(e) });
        std.process.exit(2);
    };
    defer allocator.free(data);

    var img = try parseImage(data, allocator);
    defer allocator.free(img.sections);

    var hex: [64]u8 = undefined;
    sha256Hex(data, &hex);
    const state = detectState(&img);
    std.debug.print("sha256: {s}\nstate:  {s}\n", .{ hex, @tagName(state) });

    if (std.mem.eql(u8, &hex, ORIGINAL_SHA256)) {
        std.debug.print("matches known stock build 1.0.7708.1297\n", .{});
    } else if (state != .original) {
        std.debug.print("note: not the known stock build - relying on signatures\n", .{});
    }

    if (want_status) return;

    if (state == .patched) {
        std.debug.print("already patched, nothing to do\n", .{});
        return;
    }
    if (state == .unknown) {
        std.debug.print("unrecognised image (partial patch or different version)\n", .{});
        std.process.exit(3);
    }

    const have_backup = blk: {
        const b = dir.readFileAlloc(io, backup, allocator, std.Io.Limit.limited(max_file)) catch break :blk false;
        defer allocator.free(b);
        var bh: [64]u8 = undefined;
        sha256Hex(b, &bh);
        break :blk std.mem.eql(u8, &bh, ORIGINAL_SHA256);
    };
    if (!have_backup) {
        dir.writeFile(io, .{ .sub_path = backup, .data = data }) catch |e| {
            std.debug.print("cannot write backup {s}: {s} (elevated shell?)\n", .{ backup, @errorName(e) });
            std.process.exit(2);
        };
        std.debug.print("backup written to {s}\n", .{backup});
    } else {
        std.debug.print("existing backup kept ({s})\n", .{backup});
    }

    _ = try buildStatusPatch(&img);
    _ = try buildGuards(&img, allocator);
    const sum = peChecksum(&img);
    std.mem.writeInt(u32, img.data[img.checksum_off..][0..4], sum, .little);
    std.debug.print("patched: {d} status sites, {d} null-guard sites, checksum 0x{x}\n", .{ status_sites.len, guard_sites.len, sum });

    if (dry_run) {
        std.debug.print("dry run, file untouched\n", .{});
        return;
    }

    const f = std.Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write }) catch |e| {
        std.debug.print("cannot open {s} for writing: {s} (elevated shell?)\n", .{ path, @errorName(e) });
        std.process.exit(2);
    };
    defer f.close(io);
    try f.writePositionalAll(io, img.data, 0);
    try f.setLength(io, img.data.len);
    std.debug.print("done. start Superluminal Performance as usual.\n", .{});
}

