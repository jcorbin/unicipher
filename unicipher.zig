const std = @import("std");

const assert = std.debug.assert;
const io = std.io;
const fs = std.fs;
const unicode = std.unicode;

const kurtisCipher = struct {
    fn cipher() Cipher {
        return .{ .encode = encode, .decode = decode };
    }

    fn encode(c0: u7, c1: u7) u21 {
        const msb0 = @intCast(u14, c0 & 0b0100_0000) >> 6;
        const msb1 = @intCast(u14, c1 & 0b0100_0000) >> 6;
        const rem0 = @intCast(u14, c0 & 0b0011_1111);
        const rem1 = @intCast(u14, c1 & 0b0011_1111);
        return @intCast(u21, ((msb0 << 1 | msb1) << 6 | rem0) << 6 | rem1);
    }

    fn decode(unic: u21) ![2]u7 {
        if (unic > std.math.maxInt(u14)) {
            return error.CodepointOutOfRange;
        }

        // 0b_ab_aaaaaa_bbbbbb
        const c = @intCast(u14, unic);
        const rem1 = @intCast(u7, c & 0b111111);
        const rem0 = @intCast(u7, (c >> 6) & 0b111111);
        const msb1 = @intCast(u7, (c >> 12) & 0b1);
        const msb0 = @intCast(u7, (c >> 13) & 0b1);
        return .{
            msb0 << 6 | rem0,
            msb1 << 6 | rem1,
        };
    }
};

const kurtisExtCipher = struct {
    fn cipher() Cipher {
        return .{ .encode = encode, .decode = decode };
    }

    fn encode(c0: u7, c1: u7) u21 {
        // So upstream works by the same scheme as above, but laid out onto 4 utf8 bytes like:
        //     240 = 0b11110_000
        //     144 = 0b10_010000 <-- 1 extra bit wired on
        //     128 = 0b10_000000
        //     128 = 0b10_000000
        // So that's just an extra 17th bit flipped:
        return kurtisCipher.encode(c0, c1) | 0b1 << 16;
    }

    fn decode(unic: u21) ![2]u7 {
        // must have only the 17th bit set outside of u14 space
        if (unic >> 14 != 0b0000100) {
            return error.CodepointOutOfRange;
        }
        return kurtisCipher.decode(unic & 0b11_111111_111111);
    }
};

const blockmixCipher = struct {
    fn cipher() Cipher {
        return .{ .encode = encode, .decode = decode };
    }

    fn encode(c0: u7, c1: u7) u21 {
        const blk1 = @intCast(u14, c0 & 0b0110_0000) >> 5;
        const blk2 = @intCast(u14, c1 & 0b0110_0000) >> 5;
        const seq0 = @intCast(u14, c0 & 0b0001_1111);
        const seq1 = @intCast(u14, c1 & 0b0001_1111);
        const blk = ~(blk1 << 2 | blk2) & 0b1111;
        return @intCast(u21, (blk << 5 | seq0) << 5 | seq1);
    }

    fn decode(unic: u21) ![2]u7 {
        if (unic > std.math.maxInt(u14)) {
            return error.CodepointOutOfRange;
        }

        // 0b_aabb_aaaaa_bbbbb
        const c = @intCast(u14, unic);
        const seq1 = @intCast(u7, c & 0b11111);
        const seq0 = @intCast(u7, (c >> 5) & 0b11111);
        const blk = @intCast(u7, (~c >> 10) & 0b1111);
        const blk1 = blk & 0b11;
        const blk0 = (blk >> 2) & 0b11;
        return .{
            blk0 << 5 | seq0,
            blk1 << 5 | seq1,
        };
    }
};

// TODO interlaveCipher -- does what it says on the tin: (0b0xxx_xxxx, 0b0yyy_yyyy) <-> 0b00xy_xyxy_xyxy_xyxy)
// TODO 3-arity variants of blockMix and interlave

const Cipher = struct {
    encode: *const fn (c0: u7, c1: u7) u21,
    decode: *const fn (unic: u21) anyerror![2]u7,

    const Self = @This();

    fn decrypt(self: Self, reader: anytype, writer: anytype) !void {
        var buf = io.bufferedReader(reader);

        // last byte written, so that we can add a final eol
        var last: ?u8 = null;
        defer if (last) |b| {
            if (b != '\n')
                writer.writeByte('\n') catch {};
        };

        // next byte to be written, so that we can trim terminal null
        var next: ?u8 = null;
        defer if (next) |b| {
            if (b != 0) {
                writer.writeByte(b) catch {};
                last = b;
            }
        };

        while (true)
            switch (readUtf8(buf.reader()) catch |err| return elideEof(err)) {
                '\n' => continue,
                else => |c| {
                    for (try self.decode(c)) |r| {
                        if (next) |b| {
                            try writer.writeByte(b);
                            last = b;
                        }
                        next = r;
                    }
                },
            };
    }

    fn encrypt(self: Self, reader: anytype, writer: anytype) !void {
        var buf = io.bufferedReader(reader);
        defer writer.writeByte('\n') catch {};
        while (true) {
            const c0 = readAscii(buf.reader()) catch |err| return elideEof(err);
            const c1 = readAscii(buf.reader()) catch null;
            if (c0 == '\n' and c1 == null) return;

            const c2 = self.encode(c0, c1 orelse 0);
            var tmp = [_]u8{0} ** 4; // maximum utf8 form is 4-bytes long
            const len = try unicode.utf8Encode(c2, &tmp);
            try writer.writeAll(tmp[0..len]);
        }
    }

    fn expectRoundTrip(self: Self, comptime in: []const u8) !void {
        std.debug.print("\n=== expect roundtrip `{s}` {any}\n", .{
            in,
            std.fmt.fmtSliceHexUpper(in),
        });

        var tmp = [_]u8{0} ** (4 * in.len);
        var out = [_]u8{0} ** (4 * in.len);

        var fix_in = io.fixedBufferStream(in);
        var fix_tmp = io.fixedBufferStream(&tmp);
        try self.encrypt(fix_in.reader(), fix_tmp.writer());
        std.debug.print("> encrypted `{s}` {any}\n", .{
            fix_tmp.getWritten(),
            std.fmt.fmtSliceHexUpper(fix_tmp.getWritten()),
        });

        var fix_retmp = io.fixedBufferStream(fix_tmp.getWritten());
        var fix_out = io.fixedBufferStream(&out);
        try self.decrypt(fix_retmp.reader(), fix_out.writer());
        std.debug.print("> decrypted `{s}` {any}\n", .{
            fix_out.getWritten(),
            std.fmt.fmtSliceHexUpper(fix_out.getWritten()),
        });

        try std.testing.expectEqualStrings(
            in,
            std.mem.trimRight(u8, fix_out.getWritten(), "\n"),
        );
    }
};

fn readAscii(reader: anytype) !u7 {
    const c = try reader.readByte();
    if (c & 0x80 != 0) return error.NonAsciiCode;
    return @intCast(u7, c);
}

fn readUtf8(reader: anytype) !u21 {
    var tmp = [_]u8{0} ** 4; // maximum utf8 form is 4-bytes long
    tmp[0] = try reader.readByte();
    const uni_len = try unicode.utf8ByteSequenceLength(tmp[0]);
    if (uni_len > 1) {
        assert(uni_len <= 4);
        try reader.readNoEof(tmp[1..uni_len]);
    }
    return try unicode.utf8Decode(tmp[0..uni_len]);
}

fn elideEof(err: anyerror) !void {
    switch (err) {
        error.EndOfStream => return,
        else => return err,
    }
}

const test_cases = [_][]const u8{
    "ad",
    "adgc",
    "bbb",
    "x",
    "another",
    "hello there",
};

test "kurtisCipher" {
    const cipher = kurtisCipher.cipher();
    inline for (test_cases) |test_case|
        try cipher.expectRoundTrip(test_case);
}

test "kurtisExtCipher" {
    const cipher = kurtisExtCipher.cipher();
    inline for (test_cases) |test_case|
        try cipher.expectRoundTrip(test_case);
}

test "blockmixCipher" {
    const cipher = blockmixCipher.cipher();
    inline for (test_cases) |test_case|
        try cipher.expectRoundTrip(test_case);
}

fn printCodes(
    reader: anytype, // io.Reader(...)
    writer: anytype, // io.Writer(...)
) !void {
    var buf = io.bufferedReader(reader);
    var tmp = [_]u8{0} ** 4; // maximum utf8 form is 4-bytes long
    while (true) {
        const c = buf.reader().readByte() catch |err| return elideEof(err);
        switch (c) {
            0x00...0x19, 0x7f => try writer.print("^{c}", .{0x40 ^ c}),
            0x20...0x7e => try writer.print(" {c}", .{c}),
            else => {
                tmp[0] = c;
                const uni_len = try unicode.utf8ByteSequenceLength(c);
                if (uni_len > 1) {
                    assert(uni_len <= 4);
                    try buf.reader().readNoEof(tmp[1..uni_len]);
                }
                const u = try unicode.utf8Decode(tmp[0..uni_len]);
                try writer.print("U+{0X} {0u}", .{u});
            },
        }
        try writer.print("\n", .{});
    }
}

fn chooseOneOf(value: anytype, arg: []const u8) ?@TypeOf(value) {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .Enum => |en| {
            inline for (en.fields) |field|
                if (std.mem.eql(u8, arg, field.name))
                    return @intToEnum(T, field.value);
            return null;
        },
        else => @compileError("chooseOneOf only works with enum values"),
    }
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    var in = io.getStdIn();
    var out = io.getStdOut();

    var mode: enum {
        decrypt,
        encrypt,
        print,
    } = .encrypt;

    var cipher: enum {
        kurtis,
        kurtisExt,
        blockmix,
    } = .kurtis;

    var args = try std.process.argsWithAllocator(arena.allocator());
    defer args.deinit();
    const prog_name = args.next() orelse "<untitled>";
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h")) {
            std.debug.print(
                \\Usage: {s} [options] [MODE=encrypt]
                \\
                \\Options:
                \\  -i FILE -- specify input file ; defaults to stdin
                \\  -o FILE -- specify output file ; defaults to stdout
                \\  -c CIPHER -- specify encrypt/decrypt cipher ; defaults to kurtis
                \\
            , .{fs.path.basename(prog_name)});

            std.debug.print("\nCiphers:\n", .{});
            inline for (@typeInfo(@TypeOf(cipher)).Enum.fields) |field|
                std.debug.print("  {s}\n", .{field.name});

            std.debug.print("\nModes:\n", .{});
            inline for (@typeInfo(@TypeOf(mode)).Enum.fields) |field|
                std.debug.print("  {s}\n", .{field.name});

            std.process.exit(0);
        } else if (std.mem.eql(u8, arg, "-i")) {
            in = try fs.cwd().openFile(args.next() orelse return error.MissingFileArg, .{});
        } else if (std.mem.eql(u8, arg, "-o")) {
            out = try fs.cwd().createFile(args.next() orelse return error.MissingFileArg, .{});
        } else if (std.mem.eql(u8, arg, "-c")) {
            cipher = chooseOneOf(
                cipher,
                args.next() orelse return error.MissingFileArg,
            ) orelse return error.InvalidCipherArg;
        } else {
            mode = chooseOneOf(mode, arg) orelse return error.InvalidMode;
        }
    }

    const cipher_inst = switch (cipher) {
        .kurtis => kurtisCipher.cipher(),
        .kurtisExt => kurtisExtCipher.cipher(),
        .blockmix => blockmixCipher.cipher(),
    };

    var bufout = io.bufferedWriter(out.writer());
    defer bufout.flush() catch {};

    try switch (mode) {
        .decrypt => cipher_inst.decrypt(in.reader(), bufout.writer()),
        .encrypt => cipher_inst.encrypt(in.reader(), bufout.writer()),
        .print => printCodes(in.reader(), bufout.writer()),
    };
}
