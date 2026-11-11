defmodule Cesr.MessagePackUtilsTest do
  alias Cesr.Version_String_1
  alias Cesr.Version_String_2
  alias Cesr.Utility.MessagePackUtils, as: MgpkUtils

  use ExUnit.Case, async: true

  test "serialize_cesr_mgpk_payload serializes" do
    {:ok, ver_str} = Version_String_2.new(%{proto: :keri, proto_major: 2,
      proto_minor: 0, genus_major: 2, genus_minor: 0, kind: :mgpk, size: 0})
    our_map = %OrdMap{tuples: [{"v", ver_str}, {"foo", %OrdMap{tuples: [{"bar", "baz"}]}}, {"wibble", "wobble"}]}
    assert MgpkUtils.serialize_cesr_mgpk_payload(our_map) ==
      {:ok, "\x83\xA1v\xB3KERICAACAAMGPKAAAy.\xA3foo\x81\xA3bar\xA3baz\xA6wibble\xA6wobble"}

    our_map_2 = %OrdMap{tuples: [{"v", ver_str}, {"foo", %OrdMap{tuples: [{"bar", "baz"}]}}, {"wibble", "wobble"},
     {"tamil", "வணக்கம"}]} # Added tamil so byte size is different than string.length
    # Note (CAL): Having some weird copy paste errors so this is the binary representation of above
    assert MgpkUtils.serialize_cesr_mgpk_payload(our_map_2) ==
      {:ok,
       <<132, 161, 118, 179, 75, 69, 82, 73, 67, 65, 65, 67, 65, 65, 77, 71,
         80, 75, 65, 65, 66, 76, 46, 163, 102, 111, 111, 129, 163, 98, 97, 114,
         163, 98, 97, 122, 166, 119, 105, 98, 98, 108, 101, 166, 119, 111, 98,
         98, 108, 101, 165, 116, 97, 109, 105, 108, 178, 224, 174, 181, 224,
         174, 163, 224, 174, 149, 224, 175, 141, 224, 174, 149, 224, 174, 174>>}
  end

  test "deserialize_cesr_mgpk_payload deserializes" do
    our_map = %OrdMap{tuples: [{"v", %Cesr.Version_String_2{
                                        genus_major: 1,
                                        genus_minor: 0,
                                        kind: :mgpk,
                                        proto: :keri,
                                        proto_major: 1,
                                        proto_minor: 0,
                                        size: 57
                                      }},
                               {"foo", %OrdMap{tuples: [{"bar", "baz"}]}}, {"wibble", "wobble"}]}
    assert MgpkUtils.deserialize_cesr_mgpk_payload("\x83\xC4\x01v\xC4\x13KERIBAABAAMGPKAAA5.\xC4\x03foo\x81\xC4\x03bar\xC4\x03baz\xC4\x06wibble\xC4\x06wobble")
      == {:ok, our_map, ""}

    our_map_2 = %OrdMap{tuples: [{"v", %Cesr.Version_String_2{
                                          genus_major: 1,
                                          genus_minor: 0,
                                          kind: :mgpk,
                                          proto: :keri,
                                          proto_major: 1,
                                          proto_minor: 0,
                                          size: 84
                                        }},
                                 {"foo", %OrdMap{tuples: [{"bar", "baz"}]}}, {"wibble", "wobble"},
                                 {"tamil", "வணக்கம"}]} # Added tamil so byte size is different than string.length
    assert MgpkUtils.deserialize_cesr_mgpk_payload("\x84\xC4\x01v\xC4\x13KERIBAABAAMGPKAABU.\xC4\x03foo\x81\xC4\x03bar\xC4\x03baz\xC4\x06wibble\xC4\x06wobble\xC4\x05tamil\xC4\x12வணக்கம")
      == {:ok, our_map_2, ""}
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

  test "Edge case, only version string serializes and deserializes" do
    # mgpk contains 3 types of fieldmaps fixmap, map16, map32.  
    # fixmap is the natural packing for a one element map but the mpgk spec
    # doesn't disallow packing one element into map16 or map32 either.
    # However, our particular msgpack implementation at the time of this
    # writing doesn't support packing into a particular fieldmap type it just
    # picks a type based on the number of elements beforehand for the developer
    # so we'll test deserialization works here but not serialization.  I did
    # open https://github.com/msgpack/msgpack-erlang/issues/103 or we can fork
    # it if this kind of thing becomes necessary in interop with another msgpk
    # implementation.
    only_ver_ordmap = %OrdMap{tuples: [{"v",
      %Cesr.Version_String_1{major: 1, minor: 0, kind: :mgpk, proto: :keri, size: 21 }}]}

    update_size = fn o, size -> 
      old_v = OrdMap.get(o, "v")
      new_v = %{old_v | size: size}
      OrdMap.put(o, "v", new_v)
    end

    only_ver_mgpk_flatmap = "\x81\xA1\x76\xB1KERI10MGPK000015_" # size 21
    only_ver_mgpk_map16 = "\xDE\x00\x01\xA1\x76\xB1KERI10MGPK000017_" # size 23
    only_ver_mgpk_map32 = "\xDF\x00\x00\x00\x01\xA1\x76\xB1KERI10MGPK000019_" # size 25
    assert MgpkUtils.serialize_cesr_mgpk_payload(only_ver_ordmap) == {:ok, only_ver_mgpk_flatmap}
    assert MgpkUtils.deserialize_cesr_mgpk_payload(only_ver_mgpk_flatmap) == {:ok, only_ver_ordmap, ""}
    assert MgpkUtils.deserialize_cesr_mgpk_payload(only_ver_mgpk_map16) == {:ok, update_size.(only_ver_ordmap, 23), ""}
    assert MgpkUtils.deserialize_cesr_mgpk_payload(only_ver_mgpk_map32) == {:ok, update_size.(only_ver_ordmap, 25), ""}

    only_ver_ordmap = %OrdMap{tuples: [{"v",
      %Cesr.Version_String_2{genus_major: 1, genus_minor: 0, kind: :mgpk,
        proto: :keri, proto_major: 1, proto_minor: 0, size: 23 }}]}
    only_ver_mgpk_flatmap = "\x81\xA1\x76\xB3KERIBAABAAMGPKAAAX." # size 23
    only_ver_mgpk_map16 = "\xDE\x00\x01\xA1\x76\xB3KERIBAABAAMGPKAAAZ." # size 25
    only_ver_mgpk_map32 = "\xDF\x00\x00\x00\x01\xA1\x76\xB3KERIBAABAAMGPKAAAb." # size 27
    assert MgpkUtils.serialize_cesr_mgpk_payload(only_ver_ordmap) == {:ok, only_ver_mgpk_flatmap}
    assert MgpkUtils.deserialize_cesr_mgpk_payload(only_ver_mgpk_flatmap) == {:ok, only_ver_ordmap, ""}
    assert MgpkUtils.deserialize_cesr_mgpk_payload(only_ver_mgpk_map16) == {:ok, update_size.(only_ver_ordmap, 25), ""}
    assert MgpkUtils.deserialize_cesr_mgpk_payload(only_ver_mgpk_map32) == {:ok, update_size.(only_ver_ordmap, 27), ""}
  end

  @doc """
    Example payloads generated from keripy using sizeify-sample-payloads.py
  """
  test "Keripy simple msgpack examples deserialize -> serialize -> deserialize" do
    Path.wildcard("test/kerilixir/example_payloads/simple/mgpk/*") |>
    Enum.map(fn (example_payload) ->
      payload_binary = File.read!(example_payload)
      {:ok, deserialized_ordmap, ""} = MgpkUtils.deserialize_cesr_mgpk_payload(payload_binary)
      {:ok, version} = Cesr.match_version(deserialized_ordmap["v"])
      {:ok, serialized_ordmap} = MgpkUtils.serialize_cesr_mgpk_payload(deserialized_ordmap)
      {:ok, deserialized_ordmap_2nd_rnd, ""} = MgpkUtils.deserialize_cesr_mgpk_payload(serialized_ordmap)
      {:ok, version2} = Cesr.match_version(deserialized_ordmap_2nd_rnd["v"])
      assert deserialized_ordmap == deserialized_ordmap_2nd_rnd
      assert version == version2
      assert serialized_ordmap == payload_binary
    end)
  end

  test "Size calculated correctly for version string 1" do
    {:ok, vers_1} = Version_String_1.new(%{proto: :keri, major: 1, minor: 0, kind: :mgpk, size: 0})
    our_map = %OrdMap{tuples: [{"v", vers_1}, {"foo", %OrdMap{tuples: [{"bar", "baz"}]}}, {"wibble", "wobble"}]}
    {:ok, serialized_map} = MgpkUtils.serialize_cesr_mgpk_payload(our_map)
    {:ok, deserialized_map, ""} = MgpkUtils.deserialize_cesr_mgpk_payload(serialized_map)
    version_string = OrdMap.get(deserialized_map, "v")
    assert byte_size(serialized_map) == version_string.size
  end

  test "Size calculated correctly for version string 2" do
    {:ok, vers_2} = Version_String_2.new(%{proto: :keri, proto_major: 2, proto_minor: 0, genus_major: 2, genus_minor: 0, kind: :mgpk, size: 0})
    our_map = %OrdMap{tuples: [{"v", vers_2}, {"foo", %OrdMap{tuples: [{"bar", "baz"}]}}, {"wibble", "wobble"}]}
    {:ok, serialized_map} = MgpkUtils.serialize_cesr_mgpk_payload(our_map)
    {:ok, deserialized_map, ""} = MgpkUtils.deserialize_cesr_mgpk_payload(serialized_map)
    version_string = OrdMap.get(deserialized_map, "v")
    assert byte_size(serialized_map) == version_string.size
  end
end
