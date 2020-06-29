# Bencode encoder/decoder

[Bencode](https://en.wikipedia.org/wiki/Bencode) is an text encoding format.
This library can encode and decode it, with an API and code close the `std.json` in the standard library.

## Decode (parse)

There are two APIs: a static one where we know at compile time what type to expect (for example in a configuratio n file), and a dynamic one where we do not know in advance what to expect
and we get a tagged union as a result.

Static API:

```zig
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
```

Dynamic API:

```zig
test "parse object into ValueTree" {
    var value_tree = try ValueTree.parse("d6:abcdef3:abc2:foi5ee", testing.allocator);
    defer {
        value_tree.deinit();
    }

    testing.expectEqualSlices(u8, value_tree.root.Object.get("abcdef").?.value.String, "abc");
    testing.expectEqual(value_tree.root.Object.get("fo").?.value.Integer, 5);
}
```


See the tests for more details, e.g about errors.

## Encode (stringify)

*TODO*
