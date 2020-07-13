# Bencode encoder/decoder

[Bencode](https://en.wikipedia.org/wiki/Bencode) is an text encoding format, not too dissimilar from JSON.
This library can encode and decode it, with an API and code close the `std.json` in the Zig standard library.
No other dependencies than the Zig standard library.

## Decode (parse)

API:

```zig
var v = try bencode.ValueTree.parse("d3:agei18e4:name3:joee", allocator);
defer v.deinit();

std.debug.warn("age={} name={}", .{
    v.root.Object.getValue("age").?.Integer,
    v.root.Object.getValue("name").?.String,
});
// Output: age=18 name=joe
```


See also the example `example.zig` and the tests for more details, e.g about errors: `zig test src/main.zig`.

### Try it out

```sh
$ zig run bencode_to_yaml.zig --  <(echo "d3:abci-99e11:hello,world3:foo8:integersli0ei5000ei-1eee")


"abc": -99
"hello,world": "foo"
"integers":
  - 0
  - 5000
  - -1

$ zig run bencode_to_yaml.zig -- ~/Downloads/debian-10.4.0-amd64-netinst.iso.torrent
<Output too big>
```

## Encode (stringify)

```zig
const Person = struct {
    age: usize,
    name: []const u8,
};
const person = Person{ .age = 18, .name = "joe" };
try bencode.stringify(person, std.io.getStdOut().writer());
// Output: d3:agei18e4:name3:joee
```

## License
BSD-3
