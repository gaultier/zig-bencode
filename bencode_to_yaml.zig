const std = @import("std");
const bencode = @import("src/main.zig");

fn dump(value: bencode.Value, indent: usize) anyerror!void {
    switch (value) {
        .Integer => |n| {
            try std.io.getStdOut().writer().print("{}", .{n});
        },
        .String => |s| {
            try std.io.getStdOut().writer().print("\"{}\"", .{s});
        },
        .Array => |arr| {
            for (arr.items) |v| {
                try std.io.getStdOut().writer().print("\n", .{});
                try std.io.getStdOut().writer().writeByteNTimes(' ', indent);
                try std.io.getStdOut().writer().print("- ", .{});
                try dump(v, indent + 2);
            }
        },
        .Object => |obj| {
            var it = obj.iterator();
            while (it.next()) |kv| {
                try std.io.getStdOut().writer().print("\n", .{});
                try std.io.getStdOut().writer().writeByteNTimes(' ', indent);
                try std.io.getStdOut().writer().print("\"{}\": ", .{kv.key});
                try dump(kv.value, indent + 2);
            }
        },
    }
}

pub fn main() anyerror!void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = &arena.allocator;

    var args = try std.process.argsAlloc(allocator);
    const arg = if (args.len == 2) args[1] else return error.MissingCliArgument;

    var value = try bencode.ValueTree.parse(arg, allocator);
    defer {
        value.deinit();
    }
    try dump(value.root, 0);
}
