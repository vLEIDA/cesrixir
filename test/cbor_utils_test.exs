defmodule Cesr.CBORUtilsTest do
  alias Cesr.Version_String_1
  alias Cesr.Version_String_2
  alias Cesr.Utility.CBORUtils

  use ExUnit.Case, async: true

  test "serialize_cesr_cbor_payload serializes" do
    our_map = %OrdMap{tuples: [{"foo", %OrdMap{tuples: [{"bar", "baz"}]}}, {"wibble", "wobble"}]}
    {:ok, ver_str} = Version_String_2.new(%{proto: :keri, proto_major: 2,
      proto_minor: 0, genus_major: 2, genus_minor: 0, kind: :cbor, size: 0})
    assert CBORUtils.serialize_cesr_cbor_payload(our_map, ver_str) ==
      {:ok, "\xA3avsKERICAACAACBORAAAy.cfoo\xA1cbarcbazfwibblefwobble"}

    our_map_2 = %OrdMap{tuples: [{"foo", %OrdMap{tuples: [{"bar", "baz"}]}}, {"wibble", "wobble"},
     {"tamil", "வணக்கம"}]} # Added tamil so byte size is different than string.length
    assert CBORUtils.serialize_cesr_cbor_payload(our_map_2, ver_str) ==
      {:ok, "\xA4avsKERICAACAACBORAABL.cfoo\xA1cbarcbazfwibblefwobbleetamilrவணக்கம"}
  end

  test "deserialize_cesr_cbor_payload deserializes" do
    our_map = %OrdMap{tuples: [{"v", "KERIBAABAACBORAAAv."},
                               {"foo", %OrdMap{tuples: [{"bar", "baz"}]}}, {"wibble", "wobble"}]}
    assert CBORUtils.deserialize_cesr_cbor_payload(
       <<163, 97, 118, 115, 75, 69, 82, 73, 66, 65, 65, 66, 65, 65, 67, 66, 79,
         82, 65, 65, 65, 118, 46, 99, 102, 111, 111, 161, 99, 98, 97, 114, 99,
         98, 97, 122, 102, 119, 105, 98, 98, 108, 101, 102, 119, 111, 98, 98,
         108, 101>>)
      == {:ok, our_map}

    our_map_2 = %OrdMap{tuples: [{"v", "KERIBAABAACBORAABW."},
                                 {"foo", %OrdMap{tuples: [{"bar", "baz"}]}}, {"wibble", "wobble"},
     {"tamil", "வணக்கம"}]} # Added tamil so byte size is different than string.length

    assert CBORUtils.deserialize_cesr_cbor_payload(
      <<164, 97, 118, 115, 75, 69, 82, 73, 66, 65, 65, 66, 65, 65, 67, 66, 79,
       82, 65, 65, 66, 87, 46, 99, 102, 111, 111, 161, 99, 98, 97, 114, 99,
       98, 97, 122, 102, 119, 105, 98, 98, 108, 101, 102, 119, 111, 98, 98,
       108, 101, 101, 116, 97, 109, 105, 108, 114, 224, 174, 181, 224, 174,
       163, 224, 174, 149, 224, 175, 141, 224, 174, 149, 224, 174, 174>>)
      == {:ok, our_map_2}
  end

  test "CBORUtils serialize serializes to an ordered map" do
    assert CBORUtils.serialize_ordmap_to_cbor(%OrdMap{
      tuples: [{"foo", %OrdMap{tuples: [{"bar", "baz"}]}}, {"wibble", "wobble"}]
    }) == {:ok, "\xA2cfoo\xA1cbarcbazfwibblefwobble"}
  end

  test "CBORUtils serialize serializes to an empty map" do
    assert CBORUtils.serialize_ordmap_to_cbor(%OrdMap{
      tuples: [{"foo", %OrdMap{tuples: []}}, {"wibble", "wobble"}]
    }) == {:ok, "\xA2cfoo\xA0fwibblefwobble"}
  end

  @doc """
    Example payloads generated from keripy using sizeify-sample-payloads.py
  """
  test "Keripy simple msgpack examples deserialize -> serialize -> deserialize" do
    Path.wildcard("test/kerilixir/example_payloads/simple/cbor/*") |>
    Enum.map(fn (example_payload) ->
      payload_binary = File.read!(example_payload)
      {:ok, deserialized_ordmap} = CBORUtils.deserialize_cesr_cbor_payload(payload_binary)
      {:ok, version} = Cesr.match_version(deserialized_ordmap["v"])
      {:ok, serialized_ordmap} = CBORUtils.serialize_cesr_cbor_payload(deserialized_ordmap, version)
      {:ok, deserialized_ordmap_2nd_rnd} = CBORUtils.deserialize_cesr_cbor_payload(serialized_ordmap)
      {:ok, version2} = Cesr.match_version(deserialized_ordmap_2nd_rnd["v"])
      assert deserialized_ordmap == deserialized_ordmap_2nd_rnd
      assert version == version2
      assert serialized_ordmap == payload_binary
    end)
  end

  test "Size calculated correctly for version string 1" do
    {:ok, vers_1} = Version_String_1.new(%{proto: :keri, major: 1, minor: 0, kind: :cbor, size: 0})
    our_map = %OrdMap{tuples: [{"foo", %OrdMap{tuples: [{"bar", "baz"}]}}, {"wibble", "wobble"}]}
    {:ok, serialized_map} = CBORUtils.serialize_cesr_cbor_payload(our_map, vers_1)
    {:ok, deserialized_map} = CBORUtils.deserialize_cesr_cbor_payload(serialized_map)
    {:ok, version_string} = Version_String_1.deserialize(OrdMap.get(deserialized_map, "v"))
    assert byte_size(serialized_map) == version_string.size
  end

  test "Size calculated correctly for version string 2" do
    {:ok, vers_2} = Version_String_2.new(%{proto: :keri, proto_major: 2,
      proto_minor: 0, genus_major: 2, genus_minor: 0, kind: :cbor, size: 0})
    our_map = %OrdMap{tuples: [{"foo", %OrdMap{tuples: [{"bar", "baz"}]}}, {"wibble", "wobble"}]}
    {:ok, serialized_map} = CBORUtils.serialize_cesr_cbor_payload(our_map, vers_2)
    {:ok, deserialized_map} = CBORUtils.deserialize_cesr_cbor_payload(serialized_map)
    {:ok, version_string} = Version_String_2.deserialize(OrdMap.get(deserialized_map, "v"))
    assert byte_size(serialized_map) == version_string.size
  end

end
