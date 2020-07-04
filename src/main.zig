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
        const value = try parseInternal(&input[0..], &arena.allocator, 0);

        return ValueTree{ .arena = arena, .root = value };
    }

    fn parseInternal(input: *[]const u8, allocator: *std.mem.Allocator, rec_count: usize) anyerror!Value {
        if (rec_count == 100) return error.RecursionLimitReached;

        if (peek(input.*)) |c| {
            return switch (c) {
                'i' => Value{ .Integer = try parseNumber(isize, input) },
                '0'...'9' => Value{ .String = try parseBytes([]const u8, u8, allocator, input) },
                'l' => {
                    var arr = Array.init(allocator);
                    errdefer arr.deinit();

                    try expectChar(input, 'l');
                    while (!match(input, 'e')) {
                        const v = try parseInternal(input, allocator, rec_count + 1);
                        try arr.append(v);
                    }
                    return Value{ .Array = arr };
                },
                'd' => {
                    var map = ObjectMap.init(allocator);
                    errdefer map.deinit();

                    try expectChar(input, 'd');
                    while (!match(input, 'e')) {
                        const k = try parseBytes([]const u8, u8, allocator, input);
                        const v = try parseInternal(input, allocator, rec_count + 1);
                        _ = try map.put(k, v);
                    }
                    return Value{ .Object = map };
                },
                else => error.UnexpectedChar,
            };
        } else return error.UnexpectedChar;
    }

    pub fn stringify(self: *const Self, out_stream: var) @TypeOf(out_stream).Error!void {
        return self.root.stringify(out_stream);
    }
};

pub const ObjectMap = std.StringHashMap(Value);
pub const Array = std.ArrayList(Value);

/// Represents a bencode value
pub const Value = union(enum) {
    Integer: isize,
    String: []const u8,
    Array: Array,
    Object: ObjectMap,

    pub fn stringifyValue(self: Value, out_stream: var) @TypeOf(out_stream).Error!void {
        switch (self) {
            .Integer => |value| {
                try out_stream.writeByte('i');
                try std.fmt.formatIntValue(value, "", std.fmt.FormatOptions{}, out_stream);
                try out_stream.writeByte('e');
            },
            .Object => |dictionary| {
                try out_stream.writeByte('d');
                var it = dictionary.iterator();
                while (it.next()) |entry| {
                    try stringify(entry.key, out_stream);
                    try entry.value.stringifyValue(out_stream);
                }
                try out_stream.writeByte('e');
                return;
            },
            .String => |s| {
                try std.fmt.formatIntValue(s.len, "", std.fmt.FormatOptions{}, out_stream);
                try out_stream.writeByte(':');
                try out_stream.writeAll(s[0..]);
                return;
            },
            .Array => |array| {
                try out_stream.writeByte('l');
                for (array.items) |x, i| {
                    try x.stringifyValue(out_stream);
                }
                try out_stream.writeByte('e');
                return;
            },
        }
    }
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

fn parseArray(comptime T: type, childType: type, allocator: *std.mem.Allocator, s: *[]const u8, rec_count: usize) anyerror!T {
    try expectChar(s, 'l');

    var arraylist = std.ArrayList(childType).init(allocator);
    errdefer {
        arraylist.deinit();
    }

    while (!match(s, 'e')) {
        const item = try parseInternal(childType, allocator, s, rec_count + 1);
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
    return parseInternal(T, allocator, &s[0..], 0);
}

/// Releases resources created by `parse`.
/// Should be called with the same type that were passed to `parse`
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

fn parseInternal(comptime T: type, allocator: *std.mem.Allocator, s: *[]const u8, rec_count: usize) anyerror!T {
    if (rec_count == 100) return error.RecursionLimitReached;

    switch (@typeInfo(T)) {
        .Int, .ComptimeInt => return parseNumber(T, s),
        .Optional => |optionalInfo| {
            return try parseInternal(optionalInfo.child, allocator, s, rec_count + 1);
        },
        .Array => |arrayInfo| {
            if (match(s, 'l')) {
                var i: usize = 0;
                var r: T = undefined;

                errdefer {
                    var j: usize = 0;
                    while (j < i) : (j += 1) {
                        parseFree(arrayInfo.child, r[j], allocator);
                    }
                }

                while (i < r.len) : (i += 1) {
                    r[i] = try parseInternal(arrayInfo.child, allocator, s, rec_count + 1);
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
                    if (n >= s.len) return error.InvalidByteLength;

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
                        @field(r, field.name) = try parseInternal(field.field_type, allocator, s, rec_count + 1);
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
                    if (parseInternal(u_field.field_type, allocator, s, rec_count + 1)) |value| {
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
                    r.* = try parseInternal(ptrInfo.child, allocator, s, rec_count + 1);
                    return r;
                },
                .Slice => {
                    const first_char = peek(s.*);
                    if (first_char) |c| {
                        if (c == 'l') return parseArray(T, ptrInfo.child, allocator, s, rec_count);
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

pub fn parseNoAlloc(comptime T: type, value: *T, s: []const u8) anyerror!void {
    return parseInternalNoAlloc(T, value, &s[0..], 0);
}

fn parseBytesNoAlloc(comptime T: type, value: *T, s: *[]const u8) anyerror!void {
    const optional_end_index = findFirstIndexOf(s.*[0..], ':');
    if (optional_end_index) |end_index| {
        if (s.*[0..end_index].len == 0) return error.MissingLengthBytes;

        const n = try std.fmt.parseInt(usize, s.*[0..end_index], 10);
        if (value.*.len != n) return error.InvalidByteLength;

        s.* = s.*[end_index..];
        try expectChar(s, ':');

        std.mem.copy(u8, value, s.*[0..n]);

        s.* = s.*[n..];
        return;
    } else {
        return error.MissingTerminatingNumberToken;
    }
}

fn parseInternalNoAlloc(comptime T: type, value: *T, s: *[]const u8, rec_count: usize) anyerror!void {
    if (rec_count == 100) return error.RecursionLimitReached;

    switch (@typeInfo(T)) {
        .Int, .ComptimeInt => {
            value.* = try parseNumber(T, s);
        },
        .Optional => |optionalInfo| {
            value.* = try parseNumber(optionalInfo.child, s);
        },
        .Array => |arrayInfo| {
            if (match(s, 'l')) {
                var i: usize = 0;

                while (i < value.*.len) : (i += 1) {
                    try parseInternalNoAlloc(arrayInfo.child, &value.*[i], s, rec_count + 1);
                }
                try expectChar(s, 'e');
                return;
            } else {
                if (arrayInfo.child != u8) return error.UnexpectedToken;
                try parseBytesNoAlloc(T, value, s);
            }
        },
        .Struct => |structInfo| {
            try expectChar(s, 'd');
            var fields_seen = [_]bool{false} ** structInfo.fields.len;

            while (!match(s, 'e')) {
                var found = false;
                inline for (structInfo.fields) |field, i| {
                    if (!fields_seen[i]) {
                        var key: [field.name.len]u8 = undefined;
                        const cpy = s.*;

                        try parseBytesNoAlloc([field.name.len]u8, &key, s);

                        if (std.mem.eql(u8, key[0..], field.name)) {
                            found = true;
                            fields_seen[i] = true;
                            try parseInternalNoAlloc(field.field_type, &@field(value, field.name), s, rec_count + 1);
                            break;
                        } else {
                            s.* = cpy;
                        }
                    }
                }
                if (!found) return error.UnknownField;
            }

            inline for (structInfo.fields) |field, i| {
                if (!fields_seen[i]) {
                    if (field.default_value) |default| {
                        @field(value, field.name) = default;
                    } else {
                        return error.MissingField;
                    }
                }
            }

            return;
        },
        // .Union => |unionInfo| {
        //     if (unionInfo.tag_type) |_| {
        //         // try each of the union fields until we find one that matches
        //         inline for (unionInfo.fields) |u_field| {
        //             if (parseInternal(u_field.field_type, allocator, s)) |value| {
        //                 return @unionInit(T, u_field.name, value);
        //             } else |err| {
        //                 // Bubble up error.OutOfMemory
        //                 // Parsing some types won't have OutOfMemory in their
        //                 // error-sets, for the condition to be valid, merge it in.
        //                 if (@as(@TypeOf(err) || error{OutOfMemory}, err) == error.OutOfMemory) return err;
        //                 // otherwise continue through the `inline for`
        //             }
        //         }
        //         return error.NoUnionMembersMatched;
        //     } else {
        //         @compileError("Unable to parse into untagged union '" ++ @typeName(T) ++ "'");
        //     }
        // },
        .Pointer => |ptrInfo| {
            switch (ptrInfo.size) {
                .One => {
                    value.* = try parseInternalNoAlloc(ptrInfo.child, s, rec_count + 1);
                    return;
                },
                .Slice => {
                    const first_char = peek(s.*);
                    if (first_char) |c| {
                        if (match(s, 'l')) {
                            var i: usize = 0;
                            while (i < value.*.len) : (i += 1) {
                                try parseInternalNoAlloc(ptrInfo.child, &value.*[i], s, rec_count + 1);
                            }
                            try expectChar(s, 'e');
                            return;
                        }
                        if (ptrInfo.child == u8) {
                            try parseBytesNoAlloc(ptrInfo.child, value, s);
                            return;
                        }
                    }
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
            inline for (S.fields) |Field, field_i| {
                // don't include void fields
                if (Field.field_type == void) continue;

                try stringify(Field.name, out_stream);
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
    testing.expectError(error.MissingSeparatingStringToken, parse([]u8, testing.allocator, "10"));
    // No way to detect this case I think since there is no terminating token
    var value = try parse([]u8, testing.allocator, "3:abcd");
    defer parseFree([]u8, value, testing.allocator);
    testing.expectEqualSlices(u8, value, "abc");
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

test "parse array into bytes with invalid size" {
    testing.expectError(error.InvalidByteLength, parse([3]u8, testing.allocator, "10:"));
}

test "parse into array too small" {
    testing.expectError(error.UnexpectedChar, parse([1][]const u8, testing.allocator, "l3:foo5:helloe"));
}

test "parse into array too big" {
    testing.expectError(error.MissingSeparatingStringToken, parse([3][]const u8, testing.allocator, "l3:foo5:helloe"));
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

    var opt: ?u16 = null;
    opt = parse(?u16, testing.allocator, "i999999999e") catch null;
    testing.expectEqual(opt, null);
}

test "parse into array and reach recursion limit" {
    testing.expectError(error.RecursionLimitReached, parse([][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][][]usize, testing.allocator, "l" ** 101 ++ "e" ** 101));
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

test "parse ValueTree and reach recursion limit" {
    testing.expectError(error.RecursionLimitReached, ValueTree.parse("l" ** 101 ++ "e" ** 101, testing.allocator));
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
}

test "stringify bytes" {
    try teststringify("3:foo", "foo");
    try teststringify("6:abcdef", "abcdef");
    try teststringify("0:", "");
    try teststringify("0:", [_]u8{});
    try teststringify("2:ab", [_]u8{ 'a', 'b' });
}

test "stringify arrays" {
    try teststringify("le", [_]isize{});
    try teststringify("li0ei5ee", [_]isize{ 0, 5 });
    try teststringify("l4:abcde", [_][]const u8{"abcd"});
}

test "stringify struct" {
    try teststringify("d3:agei18e4:name3:joee", struct { age: usize, name: []const u8 }{ .age = 18, .name = "joe" });
}

test "stringify tagged unions" {
    try teststringify("i42e", union(enum) {
        Foo: u32,
        Bar: []const u8,
    }{ .Foo = 42 });
}

test "stringify struct with void field" {
    try teststringify("d3:fooi42ee", struct {
        foo: u32,
        bar: void = {},
    }{ .foo = 42 });
}

test "stringify array of structs" {
    const MyStruct = struct {
        foo: u32,
    };
    try teststringify("ld3:fooi42eed3:fooi100eed3:fooi1000eee", [_]MyStruct{
        MyStruct{ .foo = 42 },
        MyStruct{ .foo = 100 },
        MyStruct{ .foo = 1000 },
    });
}

test "stringify vector" {
    try teststringify("li1ei1ee", @splat(2, @as(u32, 1)));
}

test "parse no alloc into bytes" {
    var bytes: [4]u8 = undefined;
    try parseNoAlloc([4]u8, &bytes, "4:abcd");
    testing.expectEqualSlices(u8, bytes[0..], "abcd");
}

test "parse no alloc into bytes of size too small" {
    var bytes: [3]u8 = undefined;
    testing.expectError(error.InvalidByteLength, parseNoAlloc([3]u8, &bytes, "4:abcd"));
}

test "parse no alloc into bytes of size too big" {
    var bytes: [5]u8 = undefined;
    testing.expectError(error.InvalidByteLength, parseNoAlloc([5]u8, &bytes, "4:abcd"));
}

test "parse no alloc into array of numbers " {
    var arr: [3]i16 = undefined;
    try parseNoAlloc([3]i16, &arr, "li1ei99ei-99ee");
    testing.expectEqualSlices(i16, arr[0..], &[_]i16{ 1, 99, -99 });
}

test "parse no alloc into array of numbers of size too small" {
    var arr: [2]i16 = undefined;
    testing.expectError(error.UnexpectedChar, parseNoAlloc([2]i16, &arr, "li1ei99ei-99ee"));
}

test "parse no alloc into array of numbers of size too big" {
    var arr: [5]i16 = undefined;
    testing.expectError(error.UnexpectedChar, parseNoAlloc([5]i16, &arr, "li1ei99ei-99ee"));
}

test "parse no alloc into array and reach recursion limit" {
    var value: [1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1]usize = undefined;

    testing.expectError(error.RecursionLimitReached, parseNoAlloc([1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1][1]usize, &value, "l" ** 111 ++ "e" ** 111));
}

test "parse no alloc into struct" {
    const TestValue = struct {
        n: i16,
        x: usize,
    };

    var value: TestValue = undefined;
    try parseNoAlloc(TestValue, &value, "d1:ni9e1:xi99ee");

    testing.expectEqual(value.n, 9);
    testing.expectEqual(value.x, 99);
}

test "parse no alloc into struct with array" {
    const TestValue = struct {
        integers: [3]i16,
        n: i16,
    };

    var value: TestValue = undefined;
    try parseNoAlloc(TestValue, &value, "d8:integersli0ei5000ei-1ee1:ni9ee");

    testing.expectEqual(value.n, 9);
    testing.expectEqual(value.integers[0], 0);
    testing.expectEqual(value.integers[1], 5_000);
    testing.expectEqual(value.integers[2], -1);
}

test "parse no alloc into struct with default value" {
    const TestValue = struct {
        n: i16,
        x: usize = 5,
    };

    var value: TestValue = undefined;
    try parseNoAlloc(TestValue, &value, "d1:ni9ee");

    testing.expectEqual(value.n, 9);
    testing.expectEqual(value.x, 5);
}
