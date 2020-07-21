const std = @import("std");
const bencode = @import("src/main.zig");

pub fn main() anyerror!void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = &arena.allocator;

    var args = try std.process.argsAlloc(allocator);
    const arg = if (args.len == 2) args[1] else return error.MissingCliArgument;

    var file = try std.fs.cwd().openFile(arg, std.fs.File.OpenFlags{ .read = true });
    defer file.close();

    const content = try file.readAllAlloc(allocator, (try file.stat()).size, std.math.maxInt(usize));

    var value = try bencode.ValueTree.parse(content, allocator);
    defer value.deinit();

    bencode.dump(&value.root, 0) catch |err| {
        try std.io.getStdErr().writer().print("Error dumping: {}\n", .{err});
        return;
    };
}
