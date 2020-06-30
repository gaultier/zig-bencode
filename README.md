# Bencode encoder/decoder

[Bencode](https://en.wikipedia.org/wiki/Bencode) is an text encoding format, not too dissimilar from JSON.
This library can encode and decode it, with an API and code close the `std.json` in the Zig standard library.
No other dependencies than the Zig standard library.

## Decode (parse)

There are two APIs: a static one where we know at compile time what type to expect (for example in a configuratio n file), and a dynamic one where we do not know in advance what to expect
and we get a tagged union as a result.

Static API:

```zig
const Person = struct {
    age: usize,
    name: []const u8,
};
const person = try bencode.parse(Person, allocator, "d3:agei18e4:name3:joee");
defer bencode.parseFree(Person, person, allocator);

// `person` is now: Person{ .age = 18, .name = "joe" };
```

Dynamic API:

```zig
var v = try bencode.ValueTree.parse("d3:agei18e4:name3:joee", allocator);
defer {
    v.deinit();
}

std.debug.warn("age={} name={}", .{
    v.root.Object.getValue("age").?.Integer,
    v.root.Object.getValue("name").?.String,
});
// Output: age=18 name=joe
```


See also the example `example.zig` and the tests for more details, e.g about errors: `zig test src/main.zig`.

### Try it out

```sh
$ zig run bencode_to_yaml.zig --  <(echo "d8:integersli0ei5000ei-1ee11:hello,world3:foo3:abci-99ee")

"integers":
  - 0
  - 5000
  - -1
"hello,world": "foo"
"abc": -99

$ zig run bencode_to_yaml.zig -- ~/Downloads/debian-10.4.0-amd64-netinst.iso.torrent
<Output too big>
```

### Deviations from the standard

- No check that dictionary keys are ordered and unique (last one wins in case of duplicates)

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

