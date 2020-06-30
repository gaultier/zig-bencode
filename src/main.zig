const std = @import("std");
const testing = std.testing;

pub const ValueTree = struct {
    arena: std.heap.ArenaAllocator,
    root: Value,

    pub fn deinit(self: *ValueTree) void {
        self.arena.deinit();
    }

    pub fn parse(input: []const u8, allocator: *std.mem.Allocator) !ValueTree {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const value = try parseInternal(&input[0..], &arena.allocator);

        return ValueTree{ .arena = arena, .root = value };
    }

    fn parseInternal(input: *[]const u8, allocator: *std.mem.Allocator) anyerror!Value {
        if (peek(input.*)) |c| {
            return switch (c) {
                'i' => Value{ .Integer = try parseNumber(isize, input) },
                '0'...'9' => Value{ .String = try parseBytes([]const u8, u8, allocator, input) },
                'l' => {
                    var arr = Array.init(allocator);

                    try expectChar(input, 'l');
                    while (!match(input, 'e')) {
                        const v = try parseInternal(input, allocator);
                        try arr.append(v);
                    }
                    return Value{ .Array = arr };
                },
                'd' => {
                    var map = ObjectMap.init(allocator);
                    try expectChar(input, 'd');
                    while (!match(input, 'e')) {
                        const k = try parseBytes([]const u8, u8, allocator, input);
                        const v = try parseInternal(input, allocator);
                        _ = try map.put(k, v);
                    }
                    return Value{ .Object = map };
                },
                else => error.UnexpectedChar,
            };
        } else return error.UnexpectedChar;
    }
};

pub const ObjectMap = std.StringHashMap(Value);
pub const Array = std.ArrayList(Value);

pub const Value = union(enum) {
    Integer: isize,
    String: []const u8,
    Array: Array,
    Object: ObjectMap,
};

fn findFirstIndexOf(s: []const u8, needle: u8) ?usize {
    for (s) |c, i| {
        if (c == needle) return i;
    }
    return null;
}

fn expectChar(s: *[]const u8, needle: u8) !void {
    if (s.*.len > 0 and s.*[0] == needle) {
        s.* = s.*[1..];
        return;
    }
    return error.UnexpectedChar;
}

fn parseNumber(comptime T: type, s: *[]const u8) anyerror!T {
    try expectChar(s, 'i');

    const optional_end_index = findFirstIndexOf(s.*[0..], 'e');
    if (optional_end_index) |end_index| {
        if (s.*[0..end_index].len == 0) return error.NoDigitsInNumber;
        const n = try std.fmt.parseInt(T, s.*[0..end_index], 10);
        if (s.*[0] == '0' and n != 0) return error.ForbiddenHeadingZeroInNumber;
        if (s.*[0] == '-' and n == 0) return error.ForbiddenNegativeZeroNumber;

        s.* = s.*[end_index..];
        try expectChar(s, 'e');

        return n;
    } else {
        return error.MissingTerminatingNumberToken;
    }
}

fn peek(s: []const u8) ?u8 {
    return if (s.len > 0) s[0] else null;
}

fn match(s: *[]const u8, needle: u8) bool {
    if (peek(s.*)) |c| {
        if (c == needle) {
            s.* = s.*[1..];
            return true;
        }
    }
    return false;
}

fn parseArray(comptime T: type, childType: type, allocator: *std.mem.Allocator, s: *[]const u8) anyerror!T {
    try expectChar(s, 'l');

    var arraylist = std.ArrayList(childType).init(allocator);
    errdefer {
        arraylist.deinit();
    }

    while (!match(s, 'e')) {
        const item = try parseInternal(childType, allocator, s);
        try arraylist.append(item);
    }

    return arraylist.toOwnedSlice();
}

fn parseBytes(comptime T: type, childType: type, allocator: *std.mem.Allocator, s: *[]const u8) anyerror!T {
    const optional_end_index = findFirstIndexOf(s.*[0..], ':');
    if (optional_end_index) |end_index| {
        if (s.*[0..end_index].len == 0) return error.MissingLengthBytes;

        const n = try std.fmt.parseInt(usize, s.*[0..end_index], 10);
        s.* = s.*[end_index..];
        try expectChar(s, ':');

        if (s.*.len < n) return error.InvalidByteLength;

        const bytes: []const u8 = s.*[0..n];
        var arraylist = std.ArrayList(childType).init(allocator);
        errdefer {
            arraylist.deinit();
        }
        try arraylist.appendSlice(bytes);

        s.* = s.*[n..];

        return arraylist.toOwnedSlice();
    }
    return error.MissingSeparatingStringToken;
}

pub fn parse(comptime T: type, allocator: *std.mem.Allocator, s: []const u8) anyerror!T {
    return parseInternal(T, allocator, &s[0..]);
}

pub fn parseFree(comptime T: type, value: T, allocator: *std.mem.Allocator) void {
    switch (@typeInfo(T)) {
        .Int, .ComptimeInt, .Enum => {},
        .Optional => {
            if (value) |v| {
                parseFree(@TypeOf(value), value, allocator);
            }
        },
        .Array => |arrayInfo| {
            for (value) |v| {
                parseFree(arrayInfo.child, v, allocator);
            }
        },
        .Union => |unionInfo| {
            if (unionInfo.tag_type) |UnionTagType| {
                inline for (unionInfo.fields) |u_field| {
                    if (@enumToInt(@as(UnionTagType, value)) == u_field.enum_field.?.value) {
                        parseFree(u_field.field_type, @field(value, u_field.name), allocator);
                        break;
                    }
                }
            } else {
                unreachable;
            }
        },
        .Struct => |structInfo| {
            inline for (structInfo.fields) |field| {
                parseFree(field.field_type, @field(value, field.name), allocator);
            }
        },
        .Pointer => |ptrInfo| {
            switch (ptrInfo.size) {
                .One => {
                    parseFree(ptrInfo.child, value.*, allocator);
                    allocator.destroy(value);
                },
                .Slice => {
                    for (value) |v| {
                        parseFree(ptrInfo.child, v, allocator);
                    }
                    allocator.free(value);
                },
                else => unreachable,
            }
        },
        else => unreachable,
    }
}

fn parseInternal(comptime T: type, allocator: *std.mem.Allocator, s: *[]const u8) anyerror!T {
    switch (@typeInfo(T)) {
        .Int, .ComptimeInt => return parseNumber(T, s),
        .Optional => |optionalInfo| {
            return try parseInternal(optionalInfo.child, allocator, s);
        },
        .Array => |arrayInfo| {
            if (match(s, 'l')) {
                var i: usize = 0;
                var r: T = undefined;

                errdefer {
                    for (r) |value| {
                        parseFree(arrayInfo.child, value, allocator);
                    }
                }

                while (i < r.len) : (i += 1) {
                    r[i] = try parseInternal(arrayInfo.child, allocator, s);
                }
                try expectChar(s, 'e');
                return r;
            } else {
                if (arrayInfo.child != u8) return error.UnexpectedToken;
                var r: T = undefined;

                const optional_end_index = findFirstIndexOf(s.*[0..], ':');
                if (optional_end_index) |end_index| {
                    if (s.*[0..end_index].len == 0) return error.MissingLengthBytes;

                    const n = try std.fmt.parseInt(usize, s.*[0..end_index], 10);
                    s.* = s.*[end_index..];
                    try expectChar(s, ':');

                    if (s.*.len != n) return error.InvalidByteLength;

                    const bytes: []const u8 = s.*[0..n];
                    std.mem.copy(u8, &r, bytes);

                    s.* = s.*[n..];
                    return r;
                } else {
                    return error.MissingTerminatingNumberToken;
                }
            }
        },
        .Struct => |structInfo| {
            try expectChar(s, 'd');
            var r: T = undefined;
            var fields_seen = [_]bool{false} ** structInfo.fields.len;
            errdefer {
                inline for (structInfo.fields) |field, i| {
                    if (fields_seen[i]) {
                        parseFree(field.field_type, @field(r, field.name), allocator);
                    }
                }
            }
            while (!match(s, 'e')) {
                const key = try parseBytes([]const u8, u8, allocator, s);
                defer {
                    parseFree([]const u8, key, allocator);
                }
                var found = false;
                inline for (structInfo.fields) |field, i| {
                    if (std.mem.eql(u8, key, field.name)) {
                        found = true;
                        fields_seen[i] = true;
                        @field(r, field.name) = try parseInternal(field.field_type, allocator, s);
                        break;
                    }
                }
                if (!found) return error.UnknownField;
            }

            inline for (structInfo.fields) |field, i| {
                if (!fields_seen[i]) {
                    if (field.default_value) |default| {
                        @field(r, field.name) = default;
                    } else {
                        return error.MissingField;
                    }
                }
            }

            return r;
        },
        .Union => |unionInfo| {
            if (unionInfo.tag_type) |_| {
                // try each of the union fields until we find one that matches
                inline for (unionInfo.fields) |u_field| {
                    if (parseInternal(u_field.field_type, allocator, s)) |value| {
                        return @unionInit(T, u_field.name, value);
                    } else |err| {
                        // Bubble up error.OutOfMemory
                        // Parsing some types won't have OutOfMemory in their
                        // error-sets, for the condition to be valid, merge it in.
                        if (@as(@TypeOf(err) || error{OutOfMemory}, err) == error.OutOfMemory) return err;
                        // otherwise continue through the `inline for`
                    }
                }
                return error.NoUnionMembersMatched;
            } else {
                @compileError("Unable to parse into untagged union '" ++ @typeName(T) ++ "'");
            }
        },
        .Pointer => |ptrInfo| {
            switch (ptrInfo.size) {
                .One => {
                    const r: T = try allocator.create(ptrInfo.child);
                    r.* = try parseInternal(ptrInfo.child, allocator, s);
                    return r;
                },
                .Slice => {
                    const first_char = peek(s.*);
                    if (first_char) |c| {
                        if (c == 'l') return parseArray(T, ptrInfo.child, allocator, s);
                        if (ptrInfo.child == u8) return parseBytes(T, ptrInfo.child, allocator, s);
                    }
                    return error.UnexpectedChar;
                },
                else => @compileError("Unable to parse into type '" ++ @typeName(T) ++ "'"),
            }
        },
        else => @compileError("Unable to parse into type '" ++ @typeName(T) ++ "'"),
    }
}

pub fn stringify(value: var, out_stream: var) @TypeOf(out_stream).Error!void {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .Int, .ComptimeInt => {
            try out_stream.writeByte('i');
            try std.fmt.formatIntValue(value, "", std.fmt.FormatOptions{}, out_stream);
            try out_stream.writeByte('e');
        },
        .Union => {
            if (comptime std.meta.trait.hasFn("bencodeStringify")(T)) {
                return value.bencodeStringify(out_stream);
            }

            const info = @typeInfo(T).Union;
            if (info.tag_type) |UnionTagType| {
                inline for (info.fields) |u_field| {
                    if (@enumToInt(@as(UnionTagType, value)) == u_field.enum_field.?.value) {
                        return try stringify(@field(value, u_field.name), out_stream);
                    }
                }
            } else {
                @compileError("Unable to stringify untagged union '" ++ @typeName(T) ++ "'");
            }
        },
        .Struct => |S| {
            if (comptime std.meta.trait.hasFn("bencodeStringify")(T)) {
                return value.bencodeStringify(out_stream);
            }

            try out_stream.writeByte('d');
            comptime var field_output = false;
            inline for (S.fields) |Field, field_i| {
                // don't include void fields
                if (Field.field_type == void) continue;

                if (!field_output) {
                    field_output = true;
                } else {
                    try out_stream.writeByte(',');
                }
                try stringify(Field.name, out_stream);
                try out_stream.writeByte(':');
                try stringify(@field(value, Field.name), out_stream);
            }
            try out_stream.writeByte('e');
            return;
        },
        .ErrorSet => return stringify(@as([]const u8, @errorName(value)), out_stream),
        .Pointer => |ptr_info| switch (ptr_info.size) {
            .One => switch (@typeInfo(ptr_info.child)) {
                .Array => {
                    const Slice = []const std.meta.Elem(ptr_info.child);
                    return stringify(@as(Slice, value), out_stream);
                },
                else => {
                    // TODO: avoid loops?
                    return stringify(value.*, out_stream);
                },
            },
            // TODO: .Many when there is a sentinel (waiting for https://github.com/ziglang/zig/pull/3972)
            .Slice => {
                if (ptr_info.child == u8) {
                    try std.fmt.formatIntValue(value.len, "", std.fmt.FormatOptions{}, out_stream);
                    try out_stream.writeByte(':');
                    try out_stream.writeAll(value[0..]);
                    return;
                }

                try out_stream.writeByte('l');
                for (value) |x, i| {
                    try stringify(x, out_stream);
                }
                try out_stream.writeByte('e');
                return;
            },
            else => @compileError("Unable to stringify type '" ++ @typeName(T) ++ "'"),
        },
        .Array => return stringify(&value, out_stream),
        .Vector => |info| {
            const array: [info.len]info.child = value;
            return stringify(&array, out_stream);
        },
        else => @compileError("Unable to stringify type '" ++ @typeName(T) ++ "'"),
    }
}

test "parse into number" {
    testing.expectEqual((try parse(u8, testing.allocator, "i20e")), 20);
}

test "parse into number with missing end token" {
    testing.expectError(error.MissingTerminatingNumberToken, parse(u8, testing.allocator, "i20"));
}

test "parse into number with missing start token" {
    testing.expectError(error.UnexpectedChar, parse(u8, testing.allocator, "20e"));
}

test "parse into number 0" {
    testing.expectEqual((try parse(u8, testing.allocator, "i0e")), 0);
}

test "parse into negative number" {
    testing.expectEqual((try parse(isize, testing.allocator, "i-42e")), -42);
}

test "parse empty string into number" {
    testing.expectError(error.UnexpectedChar, parse(isize, testing.allocator, ""));
}

test "parse negative zero into number" {
    testing.expectError(error.ForbiddenNegativeZeroNumber, parse(isize, testing.allocator, "i-0e"));
}

test "parse into overflowing number" {
    testing.expectError(error.Overflow, parse(u8, testing.allocator, "i256e"));
    testing.expectError(error.Overflow, parse(i8, testing.allocator, "i-129e"));
}

test "parse into number with heading 0" {
    testing.expectError(error.ForbiddenHeadingZeroInNumber, parse(u8, testing.allocator, "i01e"));
}

test "parse into number without digits" {
    testing.expectError(error.MissingTerminatingNumberToken, parse(u8, testing.allocator, "i"));
    testing.expectError(error.NoDigitsInNumber, parse(u8, testing.allocator, "ie"));
}

test "parse into bytes" {
    const res = try parse([]u8, testing.allocator, "3:abc");
    defer {
        testing.allocator.free(res);
    }
    testing.expectEqualSlices(u8, res, "abc");
}

test "parse into unicode bytes" {
    const res = try parse([]u8, testing.allocator, "9:毛泽东");
    defer {
        testing.allocator.free(res);
    }
    testing.expectEqualSlices(u8, res, "毛泽东");
}

test "parse into bytes with invalid size" {
    testing.expectError(error.InvalidByteLength, parse([]u8, testing.allocator, "10:foo"));
    testing.expectError(error.InvalidByteLength, parse([]u8, testing.allocator, "10:"));
}

test "parse empty string into bytes" {
    testing.expectError(error.UnexpectedChar, parse([]u8, testing.allocator, ""));
}

test "parse into bytes with missing length" {
    testing.expectError(error.MissingLengthBytes, parse([]u8, testing.allocator, ":"));
}

test "parse into bytes with missing separator" {
    testing.expectError(error.MissingSeparatingStringToken, parse([]u8, testing.allocator, "4"));
}

test "parse into empty array" {
    const res = try parse([]u8, testing.allocator, "le");
    defer {
        testing.allocator.free(res);
    }
    testing.expectEqual(res.len, 0);
}

test "parse into array of u8 numbers" {
    const res = try parse([]u8, testing.allocator, "li4ei10ee");
    defer {
        testing.allocator.free(res);
    }
    const arr = [_]u8{ 4, 10 };
    testing.expectEqualSlices(u8, res, arr[0..]);
}

test "parse into array of isize numbers" {
    const res = try parse([]isize, testing.allocator, "li-4ei500ee");
    defer {
        testing.allocator.free(res);
    }
    const arr = [_]isize{ -4, 500 };
    testing.expectEqualSlices(isize, res, arr[0..]);
}

test "parse into empty array of bytes" {
    const res = try parse([][]const u8, testing.allocator, "le");
    defer {
        testing.allocator.free(res);
    }
    const arr = [_][]const u8{};
    testing.expectEqual(res.len, 0);
}

test "parse into array of bytes" {
    var res = try parse([][]const u8, testing.allocator, "l3:foo5:helloe");
    defer {
        parseFree([][]const u8, res, testing.allocator);
    }
    const arr = [_][]const u8{ "foo", "hello" };
    testing.expectEqual(res.len, 2);
    testing.expectEqualSlices(u8, res[0], "foo");
    testing.expectEqualSlices(u8, res[1], "hello");
}

test "parse into heterogeneous array" {
    const TestValue = union(enum) { Integer: isize, String: []const u8 };

    var res = try parse([]TestValue, testing.allocator, "l3:fooi20ee");
    defer {
        parseFree([]TestValue, res, testing.allocator);
    }
    testing.expectEqual(res.len, 2);
    testing.expectEqualSlices(u8, res[0].String, "foo");
    testing.expectEqual(res[1].Integer, 20);
}

test "parse into pointer" {
    const value = try parse(*i8, testing.allocator, "i7e");
    defer {
        parseFree(*i8, value, testing.allocator);
    }
    testing.expectEqual(value.*, 7);
}

test "parse into array" {
    const value = try parse([2][]const u8, testing.allocator, "l3:foo5:helloe");
    defer {
        parseFree([2][]const u8, value, testing.allocator);
    }
    const slice = [2][]const u8{ "foo", "hello" };
    testing.expectEqual(value.len, 2);
    testing.expectEqualSlices(u8, value[0], "foo");
    testing.expectEqualSlices(u8, value[1], "hello");
}

test "parse bytes into array" {
    testing.expectEqual(try parse([2]u8, testing.allocator, "2:fo"), @as([2]u8, "fo".*));
}

test "parse into array with missing terminator" {
    testing.expectError(error.UnexpectedChar, parse([2][]const u8, testing.allocator, "l3:foo5:hello"));
}

test "parse into struct" {
    const TestValue = struct {
        n: i16,
        integers: [3]i16,
    };

    const value = try parse(TestValue, testing.allocator, "d8:integersli0ei5000ei-1ee1:ni9ee");
    defer {
        parseFree(TestValue, value, testing.allocator);
    }

    testing.expectEqual(value.n, 9);
    testing.expectEqual(value.integers[0], 0);
    testing.expectEqual(value.integers[1], 5_000);
    testing.expectEqual(value.integers[2], -1);
}

test "parse into struct with missing fields, using default values" {
    const TestValue = struct {
        n: i16 = 0,
        integers: [3]i16,
    };

    const value = try parse(TestValue, testing.allocator, "d8:integersli0ei5000ei-1eee");
    defer {
        parseFree(TestValue, value, testing.allocator);
    }

    testing.expectEqual(value.n, 0);
    testing.expectEqual(value.integers[0], 0);
    testing.expectEqual(value.integers[1], 5_000);
    testing.expectEqual(value.integers[2], -1);
}

test "parse into struct with missing fields, without default values" {
    const TestValue = struct {
        n: i16,
        integers: [3]i16,
    };

    testing.expectError(error.MissingField, parse(TestValue, testing.allocator, "d8:integersli0ei5000ei-1eee"));
}

test "parse into struct with unkown field" {
    const TestValue = struct {
        integers: [3]i16,
    };

    testing.expectError(error.UnknownField, parse(TestValue, testing.allocator, "d8:integersli0ei5000ei-1ee1:ni9ee"));
}

test "parse into empty struct" {
    const TestValue = struct {};

    testing.expectEqual(try parse(TestValue, testing.allocator, "de"), TestValue{});
    testing.expectError(error.UnknownField, parse(TestValue, testing.allocator, "d1:ni9eee"));
}

test "parse into optional" {
    testing.expectEqual(try parse(?isize, testing.allocator, "i5e"), 5);
}

test "parse number into ValueTree" {
    const value_tree = try ValueTree.parse("i-1e", testing.allocator);
    testing.expectEqual(value_tree.root.Integer, -1);
}

test "parse bytes into ValueTree" {
    var value_tree = try ValueTree.parse("9:abcdefghi", testing.allocator);
    defer {
        value_tree.deinit();
    }

    testing.expectEqualSlices(u8, value_tree.root.String, "abcdefghi");
}

test "parse empty array into ValueTree" {
    var value_tree = try ValueTree.parse("le", testing.allocator);
    defer {
        value_tree.deinit();
    }

    testing.expectEqual(value_tree.root.Array.items.len, 0);
}

test "parse array into ValueTree" {
    var value_tree = try ValueTree.parse("l6:abcdefi0ee", testing.allocator);
    defer {
        value_tree.deinit();
    }

    testing.expectEqualSlices(u8, value_tree.root.Array.items[0].String, "abcdef");
    testing.expectEqual(value_tree.root.Array.items[1].Integer, 0);
}

test "parse object into ValueTree" {
    var value_tree = try ValueTree.parse("d6:abcdef3:abc2:foi5ee", testing.allocator);
    defer {
        value_tree.deinit();
    }

    testing.expectEqualSlices(u8, value_tree.root.Object.get("abcdef").?.value.String, "abc");
    testing.expectEqual(value_tree.root.Object.get("fo").?.value.Integer, 5);
}

fn teststringify(expected: []const u8, value: var) !void {
    const ValidationOutStream = struct {
        const Self = @This();
        pub const OutStream = std.io.OutStream(*Self, Error, write);
        pub const Error = error{
            TooMuchData,
            DifferentData,
        };

        expected_remaining: []const u8,

        fn init(exp: []const u8) Self {
            return .{ .expected_remaining = exp };
        }

        pub fn outStream(self: *Self) OutStream {
            return .{ .context = self };
        }

        fn write(self: *Self, bytes: []const u8) Error!usize {
            if (self.expected_remaining.len < bytes.len) {
                std.debug.warn(
                    \\====== expected this output: =========
                    \\{}
                    \\======== instead found this: =========
                    \\{}
                    \\======================================
                , .{
                    self.expected_remaining,
                    bytes,
                });
                return error.TooMuchData;
            }
            if (!std.mem.eql(u8, self.expected_remaining[0..bytes.len], bytes)) {
                std.debug.warn(
                    \\====== expected this output: =========
                    \\{}
                    \\======== instead found this: =========
                    \\{}
                    \\======================================
                , .{
                    self.expected_remaining[0..bytes.len],
                    bytes,
                });
                return error.DifferentData;
            }
            self.expected_remaining = self.expected_remaining[bytes.len..];
            return bytes.len;
        }
    };

    var vos = ValidationOutStream.init(expected);
    try stringify(value, vos.outStream());
    if (vos.expected_remaining.len > 0) return error.NotEnoughData;
}

test "stringify number" {
    try teststringify("i0e", 0);
    try teststringify("i9e", 9);
    try teststringify("i-345e", -345);

    try teststringify("3:foo", "foo");
    try teststringify("6:abcdef", "abcdef");
    try teststringify("0:", "");
    try teststringify("0:", [_]u8{});
    try teststringify("2:ab", [_]u8{ 'a', 'b' });

    try teststringify("le", [_]isize{});
}
