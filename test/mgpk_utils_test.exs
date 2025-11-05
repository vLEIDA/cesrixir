defmodule Cesr.MessagePackUtilsTest do
  alias Cesr.Version_String_1
  alias Cesr.Version_String_2
  alias Cesr.Utility.MessagePackUtils, as: MgpkUtils

  use ExUnit.Case, async: true

  test "serialize_cesr_mgpk_payload serializes" do
    our_map = %OrdMap{tuples: [{"foo", %OrdMap{tuples: [{"bar", "baz"}]}}, {"wibble", "wobble"}]}
    {:ok, ver_str} = Version_String_2.new(%{proto: :keri, proto_major: 2,
      proto_minor: 0, genus_major: 2, genus_minor: 0, kind: :mgpk, size: 0})
    assert MgpkUtils.serialize_cesr_mgpk_payload(our_map, ver_str) ==
      {:ok, "\x83\xA1v\xB3KERICAACAAMGPKAAAy.\xA3foo\x81\xA3bar\xA3baz\xA6wibble\xA6wobble"}

    our_map_2 = %OrdMap{tuples: [{"foo", %OrdMap{tuples: [{"bar", "baz"}]}}, {"wibble", "wobble"},
     {"tamil", "வணக்கம"}]} # Added tamil so byte size is different than string.length
    # Note (CAL): Having some weird copy paste errors so this is the binary representation of above
    assert MgpkUtils.serialize_cesr_mgpk_payload(our_map_2, ver_str) ==
      {:ok,
       <<132, 161, 118, 179, 75, 69, 82, 73, 67, 65, 65, 67, 65, 65, 77, 71,
         80, 75, 65, 65, 66, 76, 46, 163, 102, 111, 111, 129, 163, 98, 97, 114,
         163, 98, 97, 122, 166, 119, 105, 98, 98, 108, 101, 166, 119, 111, 98,
         98, 108, 101, 165, 116, 97, 109, 105, 108, 178, 224, 174, 181, 224,
         174, 163, 224, 174, 149, 224, 175, 141, 224, 174, 149, 224, 174, 174>>}
  end

  test "deserialize_cesr_mgpk_payload deserializes" do
    our_map = %OrdMap{tuples: [{"v", "KERIBAAMGPKAAA-."},
                               {"foo", %OrdMap{tuples: [{"bar", "baz"}]}}, {"wibble", "wobble"}]}
    assert MgpkUtils.deserialize_cesr_mgpk_payload("\x83\xC4\x01v\xC4\x10KERIBAAMGPKAAA-.\xC4\x03foo\x81\xC4\x03bar\xC4\x03baz\xC4\x06wibble\xC4\x06wobble")
      == {:ok, our_map}

    our_map_2 = %OrdMap{tuples: [{"v", "KERIBAAMGPKAABb."},
                                 {"foo", %OrdMap{tuples: [{"bar", "baz"}]}}, {"wibble", "wobble"},
     {"tamil", "வணக்கம"}]} # Added tamil so byte size is different than string.length
    assert MgpkUtils.deserialize_cesr_mgpk_payload("\x84\xC4\x01v\xC4\x10KERIBAAMGPKAABb.\xC4\x03foo\x81\xC4\x03bar\xC4\x03baz\xC4\x06wibble\xC4\x06wobble\xC4\x05tamil\xC4\x12வணக்கம")
      == {:ok, our_map_2}
  end

  test "MGPKUtils serialize serializes to an ordered map" do
    assert MgpkUtils.serialize_ordmap_to_mgpk(%OrdMap{
      tuples: [{"foo", %OrdMap{tuples: [{"bar", "baz"}]}}, {"wibble", "wobble"}]
    }) == {:ok, "\x82\xA3foo\x81\xA3bar\xA3baz\xA6wibble\xA6wobble"}
  end

  test "MGPKUtils serialize serializes to an empty map" do
    assert MgpkUtils.serialize_ordmap_to_mgpk(%OrdMap{
      tuples: [{"foo", %OrdMap{tuples: []}}, {"wibble", "wobble"}]
    }) == {:ok, "\x82\xA3foo\x90\xA6wibble\xA6wobble"}
  end

  @doc """
    Example payloads generated from keripy using sizeify-sample-payloads.py
  """
  test "Keripy simple msgpack examples deserialize -> serialize -> deserialize" do
    Path.wildcard("test/kerilixir/example_payloads/simple/mgpk/*") |>
    Enum.map(fn (example_payload) ->
      payload_binary = File.read!(example_payload)
      {:ok, deserialized_ordmap} = MgpkUtils.deserialize_cesr_mgpk_payload(payload_binary)
      {:ok, version} = Cesr.match_version(deserialized_ordmap["v"])
      {:ok, serialized_ordmap} = MgpkUtils.serialize_cesr_mgpk_payload(deserialized_ordmap, version)
      {:ok, deserialized_ordmap_2nd_rnd} = MgpkUtils.deserialize_cesr_mgpk_payload(serialized_ordmap)
      {:ok, version2} = Cesr.match_version(deserialized_ordmap_2nd_rnd["v"])
      assert deserialized_ordmap == deserialized_ordmap_2nd_rnd
      assert version == version2
      assert serialized_ordmap == payload_binary
    end)
  end

  test "Size calculated correctly for version string 1" do
    {:ok, vers_1} = Version_String_1.new(%{proto: :keri, major: 1, minor: 0, kind: :mgpk, size: 0})
    our_map = %OrdMap{tuples: [{"foo", %OrdMap{tuples: [{"bar", "baz"}]}}, {"wibble", "wobble"}]}
    {:ok, serialized_map} = MgpkUtils.serialize_cesr_mgpk_payload(our_map, vers_1)
    {:ok, deserialized_map} = MgpkUtils.deserialize_cesr_mgpk_payload(serialized_map)
    {:ok, version_string} = Version_String_1.deserialize(OrdMap.get(deserialized_map, "v"))
    assert byte_size(serialized_map) == version_string.size
  end

  test "Size calculated correctly for version string 2" do
    {:ok, vers_2} = Version_String_2.new(%{proto: :keri, proto_major: 2, proto_minor: 0, genus_major: 2, genus_minor: 0, kind: :mgpk, size: 0})
    our_map = %OrdMap{tuples: [{"foo", %OrdMap{tuples: [{"bar", "baz"}]}}, {"wibble", "wobble"}]}
    {:ok, serialized_map} = MgpkUtils.serialize_cesr_mgpk_payload(our_map, vers_2)
    {:ok, deserialized_map} = MgpkUtils.deserialize_cesr_mgpk_payload(serialized_map)
    {:ok, version_string} = Version_String_2.deserialize(OrdMap.get(deserialized_map, "v"))
    assert byte_size(serialized_map) == version_string.size
  end

end
