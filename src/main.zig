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
                    var map = ObjectMap.init(mapCompare);

                    try expectChar(input, 'd');
                    while (!match(input, 'e')) {
                        const k = try parseBytes([]const u8, u8, allocator, input);
                        const v = try parseInternal(input, allocator, rec_count + 1);
                        var entry: *Entry = try allocator.create(Entry);
                        errdefer allocator.destroy(entry);

                        entry.*.key = k;
                        entry.*.value = v;
                        if (map.insert(&entry.*.node) != null) {
                            return error.DuplicateDictionaryKeys; // EEXISTS
                        }

                        const next_key = entry.*.node.next();
                        if (next_key != null) {
                            return error.UnorderedDictionaryKeys;
                        }
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

pub const ObjectMap = std.rb.Tree;
pub const Entry = struct {
    node: std.rb.Node,
    key: []const u8,
    value: Value,
};

fn mapGetEntry(node: *std.rb.Node) *Entry {
    return @fieldParentPtr(Entry, "node", node);
}

fn mapCompare(l: *std.rb.Node, r: *std.rb.Node, contextIgnore: *std.rb.Tree) std.math.Order {
    var left = mapGetEntry(l);
    var right = mapGetEntry(r);

    return std.mem.order(u8, left.key, right.key);
}

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

                var node = dictionary.first();
                var entry = mapGetEntry(&node);

                while (node.node.next()) |entry| {
                    try stringify(entry.key, out_stream);
                    try entry.value.stringifyValue(out_stream);

                    node = node.next();
                    entry = mapGetEntry(&node);
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

test "parse into number" {
    testing.expectEqual((try ValueTree.parse("i20e", testing.allocator)).root.Integer, 20);
}

test "parse into number with missing end token" {
    testing.expectError(error.MissingTerminatingNumberToken, ValueTree.parse("i20", testing.allocator));
}

test "parse into number with missing start token" {
    testing.expectError(error.UnexpectedChar, ValueTree.parse("20e", testing.allocator));
}

test "parse into number 0" {
    testing.expectEqual((try ValueTree.parse("i0e", testing.allocator)).root.Integer, 0);
}

test "parse into negative number" {
    testing.expectEqual((try ValueTree.parse("i-42e", testing.allocator)).root.Integer, -42);
}

test "parse empty string into number" {
    testing.expectError(error.UnexpectedChar, ValueTree.parse("", testing.allocator));
}

test "parse negative zero into number" {
    testing.expectError(error.ForbiddenNegativeZeroNumber, ValueTree.parse("i-0e", testing.allocator));
}

test "parse into overflowing number" {
    testing.expectError(error.Overflow, ValueTree.parse("i256e", testing.allocator));
    testing.expectError(error.Overflow, ValueTree.parse("i-129e", testing.allocator));
}

test "parse into number with heading 0" {
    testing.expectError(error.ForbiddenHeadingZeroInNumber, ValueTree.parse("i01e", testing.allocator));
}

test "parse into number without digits" {
    testing.expectError(error.MissingTerminatingNumberToken, ValueTree.parse("i", testing.allocator));
    testing.expectError(error.NoDigitsInNumber, ValueTree.parse("ie", testing.allocator));
}

test "parse into bytes" {
    const res = (try ValueTree.parse("3:abc", testing.allocator)).root.String;
    defer testing.allocator.free(res);

    testing.expectEqualSlices(u8, res, "abc");
}

test "parse into unicode bytes" {
    const res = (try ValueTree.parse("9:毛泽东", testing.allocator)).root.String;
    defer testing.allocator.free(res);

    testing.expectEqualSlices(u8, res, "毛泽东");
}

test "parse into bytes with invalid size" {
    testing.expectError(error.InvalidByteLength, ValueTree.parse("10:foo", testing.allocator));
    testing.expectError(error.InvalidByteLength, ValueTree.parse("10:", testing.allocator));
    testing.expectError(error.MissingSeparatingStringToken, ValueTree.parse("10", testing.allocator));
    // No way to detect this case I think since there is no terminating token
    var value = (try ValueTree.parse("3:abcd", testing.allocator));
    defer value.deinit();
    testing.expectEqualSlices(u8, value.root.String, "abc");
}

test "parse empty string into bytes" {
    testing.expectError(error.UnexpectedChar, ValueTree.parse("", testing.allocator));
}

test "parse into bytes with missing length" {
    testing.expectError(error.MissingLengthBytes, ValueTree.parse(":", testing.allocator));
}

test "parse into bytes with missing separator" {
    testing.expectError(error.MissingSeparatingStringToken, ValueTree.parse("4", testing.allocator));
}

test "parse into empty array" {
    const res = (try ValueTree.parse("le", testing.allocator)).root.Array;
    defer testing.allocator.free(res);

    testing.expectEqual(res.items.len, 0);
}

test "parse into array of u8 numbers" {
    const res = (try ValueTree.parse("li4ei10ee", testing.allocator)).root.Array;
    defer testing.allocator.free(res);

    testing.expectEqual(res.items.len, 2);
    testing.expectEqual(res.items[0].Integer, 4);
    testing.expectEqual(res.items[1].Integer, 10);
}

test "parse into array of isize numbers" {
    const res = (try ValueTree.parse("li-4ei500ee", testing.allocator)).root.Array;
    defer testing.allocator.free(res);

    testing.expectEqual(res.items.len, 2);
    testing.expectEqual(res.items[0].Integer, -4);
    testing.expectEqual(res.items[1].Integer, 500);
}

test "parse into empty array of bytes" {
    const res = (try ValueTree.parse("le", testing.allocator)).root.Array;
    defer testing.allocator.free(res);

    testing.expectEqual(res.items.len, 0);
}

test "parse into array of bytes" {
    var res = try ValueTree.parse("l3:foo5:helloe", testing.allocator);
    defer res.deinit();

    testing.expectEqual(res.root.Array.items.len, 2);
    testing.expectEqualSlices(u8, res.root.Array.items[0].String, "foo");
    testing.expectEqualSlices(u8, res.root.Array.items[1].String, "hello");
}

test "parse into heterogeneous array" {
    var res = try ValueTree.parse("l3:fooi20ee", testing.allocator);
    defer res.deinit();

    testing.expectEqual(res.root.Array.items.len, 2);
    testing.expectEqualSlices(u8, res.root.Array.items[0].String, "foo");
    testing.expectEqual(res.root.Array.items[1].Integer, 20);
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

test "parse object into ValueTree with duplicate keys" {
    testing.expectError(error.DuplicateDictionaryKeys, ValueTree.parse("d1:ni9e1:ni9ee", testing.allocator));
}

test "parse object into ValueTree with unordered keys" {
    testing.expectError(error.UnorderedDictionaryKeys, ValueTree.parse("d1:ni9e1:mi9ee", testing.allocator));
}

test "parse object into ValueTree" {
    var value_tree = try ValueTree.parse("d6:abcdef3:abc2:foi5ee", testing.allocator);
    defer {
        value_tree.deinit();
    }

    var entry: Entry = undefined;
    entry.key = "abcdef";
    var node = mapGetEntry(value_tree.root.Object.lookup(&entry.node).?);

    testing.expectEqualSlices(u8, node.value.String, "abc");

    entry.key = "fo";
    node = mapGetEntry(value_tree.root.Object.lookup(&entry.node).?);
    testing.expectEqual(node.value.Integer, 5);
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
