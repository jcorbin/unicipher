const std = @import("std");

const assert = std.debug.assert;
const io = std.io;
const unicode = std.unicode;

fn readAscii(
    reader: anytype, // io.Reader(...)
) !u7 {
    const c = try reader.readByte();
    if (c & 0x80 != 0) return error.NonAsciiCode;
    return @intCast(u7, c);
}

fn readUtf8(
    reader: anytype, // io.Reader(...)
) !u21 {
    var tmp = [_]u8{0} ** 4; // maximum utf8 form is 4-bytes long
    tmp[0] = try reader.readByte();
    const uni_len = try unicode.utf8ByteSequenceLength(tmp[0]);
    if (uni_len > 1) {
        assert(uni_len <= 4);
        try reader.readNoEof(tmp[1..uni_len]);
    }
    return try unicode.utf8Decode(tmp[0..uni_len]);
}

const kurtisCipher = struct {
    fn encode(c0: u7, maybe_c1: ?u7) u15 {
        const c1 = maybe_c1 orelse 0;
        const have_c1 = maybe_c1 != null;
        const msb0 = @intCast(u15, c0 & 0b0100_0000) >> 6;
        const msb1 = @intCast(u15, c1 & 0b0100_0000) >> 6;
        const rem0 = @intCast(u15, c0 & 0b0011_1111);
        const rem1 = @intCast(u15, c1 & 0b0011_1111);
        const hi =
            msb0 << 1 | msb1 |
            @as(u15, if (have_c1) 0 else 4);
        return (hi << 6 | rem0) << 6 | rem1;
    }

    fn decode(unic: u21) !struct { c0: u7, c1: ?u7 } {
        if (unic > std.math.maxInt(u15)) {
            return error.InvalidKurtisCipherCode;
        }

        // 0bhab_aaaaaa_bbbbbb
        const c = @intCast(u15, unic);
        const have_c1 = c & 0b100_000000_000000 == 0;
        const rem1 = @intCast(u7, c & 0b111111);
        const rem0 = @intCast(u7, (c >> 6) & 0b111111);
        const msb1 = @intCast(u7, (c >> 12) & 0b1);
        const msb0 = @intCast(u7, (c >> 13) & 0b1);
        return .{
            .c0 = msb0 << 6 | rem0,
            .c1 = if (have_c1) msb1 << 6 | rem1 else null,
        };
    }
};

// TODO blockMixCipher -- using 2/5 ascii mechanical sympathy, rather than the 1/6 msb split ala kurtis
// TODO interlaveCipher -- does what it says on the tin: (0b0xxx_xxxx, 0b0yyy_yyyy) <-> 0b00xy_xyxy_xyxy_xyxy)
// TODO 3-arity variants of blockMix and interlave

fn elideEof(err: anyerror) !void {
    switch (err) {
        error.EndOfStream => return,
        else => return err,
    }
}

fn encrypt(
    reader: anytype, // io.Reader(...)
    writer: anytype, // io.Writer(...)
) !void {
    var buf = io.bufferedReader(reader);
    while (true) {
        const c0 = readAscii(buf.reader()) catch |err| return elideEof(err);
        const c1 = readAscii(buf.reader()) catch null;

        const c2 = kurtisCipher.encode(c0, c1);
        var tmp = [_]u8{0} ** 4; // maximum utf8 form is 4-bytes long
        const len = try unicode.utf8Encode(c2, &tmp);
        try writer.writeAll(tmp[0..len]);
    }
}

fn decrypt(
    reader: anytype, // io.Reader(...)
    writer: anytype, // io.Writer(...)
) !void {
    var buf = io.bufferedReader(reader);
    while (true) {
        const c = readUtf8(buf.reader()) catch |err| return elideEof(err);

        const r = try kurtisCipher.decode(c);
        try writer.writeByte(r.c0);
        if (r.c1) |c1| try writer.writeByte(c1);
    }
}

test "per kurtis" {
    const test_cases = [_][]const u8{
        "ad",
        "adgc",
        "bbb",
        "x",
        "another",
    };

    for (test_cases) |test_case| {
        std.debug.print("\n=== test case `{s}` {any}\n", .{
            test_case,
            std.fmt.fmtSliceHexUpper(test_case),
        });

        var tmp = [_]u8{0} ** 128;
        var out = [_]u8{0} ** 128;

        var fix_in = io.fixedBufferStream(test_case);
        var fix_tmp = io.fixedBufferStream(&tmp);
        try encrypt(fix_in.reader(), fix_tmp.writer());
        std.debug.print("> encrypted `{s}` {any}\n", .{
            fix_tmp.getWritten(),
            std.fmt.fmtSliceHexUpper(fix_tmp.getWritten()),
        });

        var fix_retmp = io.fixedBufferStream(fix_tmp.getWritten());
        var fix_out = io.fixedBufferStream(&out);
        try decrypt(fix_retmp.reader(), fix_out.writer());
        std.debug.print("> decrypted `{s}` {any}\n", .{
            fix_out.getWritten(),
            std.fmt.fmtSliceHexUpper(fix_out.getWritten()),
        });

        try std.testing.expectEqualStrings(test_case, fix_out.getWritten());
    }
}

pub fn main() !void {
    var in = io.getStdIn();
    var out = io.getStdOut();

    // TODO parse args for
    //      - alternate in/out files
    //      - mode selection
    //      - cipher selection

    var bufout = io.bufferedWriter(out.writer());
    defer bufout.flush() catch {};

    // TODO dispatch mode
    try encrypt(
        in.reader(),
        bufout.writer(),
        // TODO pass cipher
    );
}
