const std = @import("std");
const bencode = @import("src/main.zig");

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = &gpa.allocator;

    var args = try std.process.argsAlloc(allocator);
    const arg = if (args.len == 2) args[1] else return error.MissingCliArgument;

    var file = try std.fs.cwd().openFile(arg, std.fs.File.OpenFlags{ .read = true });
    defer file.close();

    const content = try file.inStream().readAllAlloc(allocator, 100_000);

    var value = try bencode.ValueTree.parse(content, allocator);
    defer value.deinit();

    bencode.dump(value.root, 0) catch |err| {
        try std.io.getStdErr().writer().print("Error dumping: {}\n", .{err});
        return;
    };
}
