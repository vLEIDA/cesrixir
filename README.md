# cesrixir
An implementation of the CESR encoding/decoding protocol of KERI protocol/genus 1.0 and 2.0 tables.

# Usage

The CESR spec defines encoding and decoding the following types of values to two encoding domains:

Field maps (of field map types from MGPK, CBOR, JSON)
Count Codes (groupings of CESR primitives or field maps or full CESR streams)
Primitives (both regular primitives and indexed primitives)

It also has support for a weird list of "annotations" tags followed by a string of arbitrary length until a newline.

The two encoding domains are binary and urlsafe b64.  The spec also refers to a
"raw" domain but this is just the name the author gives to values instantiated
at runtime from the encoding domain (ie the values you work with as a developer).

See: https://trustoverip.github.io/kswg-cesr-specification/#performant-resynchronization-with-unique-start-bits
if you want the details.

## Instantiating Cesr elements.

### Field Maps

**All field maps must be ordered maps in the CESR spec!** this presents
something of a difficulty in Elixir/Erlang where all maps don't garuntee order
for performance reasons.  We have chosen to use the ord\_map library from
hex.pm which is fine although may have problems scaling in the future.

Similarly, if you are ever going to encode your Ordmap the "kind" of
serialization you'll do is controlled by the Version String as these version
strings are specified in the spec and are required for the field maps to fit
into the TLV scheme.  These kinds are :cbor, :json, :mgpk respectively.

So unless you know what you're doing all KERI/ACDC/TSP other field maps as may
rely on CESR are instantiated as an ordmap with a version string.  *The size
will be overwritten at encoding time with the proper version string size and
can only be relied on when decoding*.

ie)
```Elixir
iex>{:ok, v} = Cesr.Version_String_1.new(%{proto: :keri, major: 1, minor: 0, kind: :json, size: 0})
iex>my_ord = OrdMap.new([{"v", v}])
```

### Count Codes and Primitives

Count codes are instantiated with lists of cesr\_elements.  We
have tried to add validation and consumption functions where we
can but this is a work in progress and these validations and
consumptions are just guesses or painful reverse engineering we've
done with keripy.  The spec author considers these semantics out
of scope for some reason.  So that being said, if something is
funny, there may be a bug or feature there to fix.

Failures should return `{:error, <err reason>}`

```Elixir
{:ok, my_yes} = Primitive.CD_1AAM_Yes.new("")
{:ok, fake_blake3} = Primitive.CD_E_Blake3_256.new(<<0::size(256)>>) # 256bit payload
{:ok, cnt_cd} = CountCodeKERIv1.CD_T_GenericGroup.new([my_yes, fake_blake3])
{:ok,
 %Cesr.CountCodeKERIv1.CD_T_GenericGroup{
   cesr_elements: [
     %Cesr.Primitive.CD_1AAM_Yes{code: "1AAM", payload: ""},
     %Cesr.Primitive.CD_E_Blake3_256{
       code: "E",
       payload: <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>
     }
   ]
 }}
```

## Encoding

This library has a set of primitives that correspond to all cesr elements that
currently exist.  At runtime these elements are all elixir structs.  To make a
well-formed cesr stream we take some of those elements in a list, nested
according to their semantics as appropriate, and then encode to one of the two
domains listed above.

```Elixir
iex>my_list_of_lists = [%CD_T_GenericGroup{cesr_elements: [%CD_1AAM_Yes{code: "1AAM", payload: ""}]}]
iex>Cesr.produce_binary_stream(my_list_of_lists)
<<249, 48, 1, 212, 0, 12>>
iex>Cesr.produce_text_stream([%CD_T_GenericGroup{cesr_elements: %CD_1AAM_Yes{cesr_elements: []}}])
"-TAB1AAM"
```

We can also take ordered maps with either a Version\_String\_1 for CESR 1.0
field maps or Version\_String\_2 for CESR 2.0 field maps as the first element
`v` field and serialize them to their field map type's representation (in this case json).

```Elixir
iex>{:ok, v} = Cesr.Version_String_1.new(%{proto: :keri, major: 1, minor: 0, kind: :json, size: 0})
iex>my_ord = OrdMap.new([{"v", v}])
iex>Cesr.produce_text_stream([my_ord])
"{\"v\":\"KERI10JSON000019_\"}"
```

Note: The size of field maps is calculated automatically per the spec.

Similarly we can put both on one stream but the consumer would have to know how
to consume all the pieces if they have some significance to each other.

```Elixir
iex>Cesr.produce_text_stream([my_ord, my_list_of_lists])
"{\"v\":\"KERI10JSON000019_\"}-TAB1AAM"
```

## Decoding

Decoding is the inverse of the above process.

### consume\_stream()

```Elixir
iex>Cesr.consume_stream("{\"v\":\"KERI10JSON000019_\"}-TAB1AAM")
[%OrdMap{tuples: [{"v", %Version_String_1{proto: :keri, major: 1, minor: 0, kind: :json, size: 25}}]}, %CD_T_GenericGroup{cesr_elements: [%CD_1AAM_Yes{code: "1AAM", payload: ""}]}]
```

Note: once again we've deserialized the size but hexidecimal 19 ==
decimal 25 in case you noticed the discrepency.

By default we choose CESR1.0 (not specified in official spec) and the keri
protocol/genus table 1.0 at some point this will change but if you'd like to
parse protocol/genus 2.0 pass :keri\_aaacaa into the stream when decoding.

```Elixir
iex>Cesr.consume_stream("{\"v\":\"KERI10JSON000019_\"}-JAB1AAM", :keri_aaacaa)
[%OrdMap{tuples: [{"v", %Version_String_1{proto: :keri, major: 1, minor: 0, kind: :json, size: 25}}]},
 %CD_J_GenericListGroup{cesr_elements: [%CD_1AAM_Yes{code: "1AAM", payload: ""}]}]
```

### consume\_primitive\_T()

There's also a confusing pattern in KERI and ACDC specs (as well as other
places) where CESR streams that *aren't* well-formed (don't abide by cold-start
requirements) can be embedded in field maps.  These are typically primitives as
far as we're aware but honestly could be count codes with our implementation.
They're just a table lookup into the protocol genus of the surrounding field
map.  You can deserialize these elements with
`consume_primitive_T(<some_b64_cesr_element>)`.

```Elixir
iex>{:ok, zero_blake3_digest} = Kerilixir.Cesr.Primitive.CD_E_Blake3_256.new(<<0::size(256)>>)
iex>Kerilixir.Cesr.CesrElement.to_b64(zero_blake3_digest)
"EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
iex>Cesr.consume_primitive_T("EAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
{:ok,
 %Cesr.Primitive.CD_E_Blake3_256{
   code: "E",
   payload: <<0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0>>
 }}
```

Note: we use a fake blake32 digest but these digests are oftentimes used as SAIDs in KERI and ACDC so you'll see them a lot.

## Examples directory
Real world CESR 1.0 streams from GLEIF are available in the
examples/gleif\_cesr\_streams directory.  Excepting the \*-vc.cesr
examples all are CESR streams similar to those used by GLEIF today.

They were taken from the wonderful
https://github.com/psteniusubi/cesr-decoder repo that we learned so
much from and was the inspiration for many of the tools in this
repo.

## Future Work

### Ordmap
As mentioned the ordmap representation uses Elixir lists (regular
linked lists) to store its tuples to keep the order.  While this
is fine and honestly the BEAM is probably the best VM in the world
for optimizing typical use cases we may outgrow this library at
scale.  A real ordered map using tries (maybe just copied from the
optimized Python implmentation) is probably going to be needed at some
point.

#### CBOR
Due to the fact that Elixir doesn't have ordered maps it was hard
to find a CBOR implementation that supported an ordered map.  We
eventually had to hack on cbor from hex ourselves and publish our
fork with ordmaps to support cbor.  At some point this work will
also have to be reconciled.

### iodata
We use binaries everywhere for simplicity.  There's probably a lot
of copying but its blazing fast and honestly we couldn't break it
in the benchmarks we put it through (probably because its just a
TLV scheme and the BEAM is optimized for that).  That being said,
iodata optimizations or just algorithmic optimizations are
probably possible.  We still feel like one more pass might
simplify a lot of this implementation.

### Streams
Similarly, a stream should probably be an elixir stream and
evaluated in place (to lower the memory usage of passing all those
binaries around).  This one is probably a good first issue for
someone with some free time.

### Bring your own code table
Honestly, the KERI protocol/genus table v1 is whats in production
at GLEIF and v2 is due to be in production ??? so you probably
won't need more code tables than this.  However, we didn't quite
have the metacoding skills in Elixir necessary to generalize the
macros more than we did.  It would be cool if you could bring your
own table defined in the CESR scheme and be able to generate code
table on the fly and stuff.  This is probably a lot of free time
for someone.

## Contributing
See [CONTRIBUTING](CONTRIBUTING.md)

## Issues
See [CONTRIBUTING](CONTRIBUTING.md)

Any bugs with the implementation please raise in this repo.  
Any bugs with the specification you can raise [here](https://github.com/trustoverip/kswg-cesr-specification)

Honestly if you think you can make this repo, the docs, or the
implementation better in some way please let us know.  We don't
know if we can accept everything but honestly every little bit
helps.
