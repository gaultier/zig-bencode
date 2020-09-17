const std = @import("std");
const bencode = @import("src/main.zig");

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = &gpa.allocator;
    const Person = struct {
        age: usize,
        name: []const u8,
    };
    const person = Person{ .age = 18, .name = "joe" };
    try bencode.stringify(person, std.io.getStdOut().writer());
}
