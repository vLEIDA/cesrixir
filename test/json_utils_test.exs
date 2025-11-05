defmodule Cesr.JsonUtilsTest do
  alias Cesr.Version_String_1
  alias Cesr.Version_String_2
  alias Cesr.Utility.JsonUtils

  use ExUnit.Case, async: true

  test "serialize_cesr_json_payload serializes" do
    {:ok, vers_2} = Version_String_2.new(%{proto: :keri, proto_major: 2,
      proto_minor: 0, genus_major: 2, genus_minor: 0, kind: :json, size: 0})
    our_map = %OrdMap{tuples: [{"foo", %OrdMap{tuples: [{"bar", "baz"}]}}, {"wibble", "wobble"}]}
    assert JsonUtils.serialize_cesr_json_payload(our_map, vers_2) ==
      {:ok, "{\"v\":\"KERICAACAAJSONAABB.\",\"foo\":{\"bar\":\"baz\"},\"wibble\":\"wobble\"}"}

    our_map_2 = %OrdMap{tuples: [{"foo", %OrdMap{tuples: [{"bar", "baz"}]}}, {"wibble", "wobble"},
     {"tamil", "வணக்கம"}]} # Added tamil so byte size is different than string.length
    assert JsonUtils.serialize_cesr_json_payload(our_map_2, vers_2) ==
      {:ok, "{\"v\":\"KERICAACAAJSONAABe.\",\"foo\":{\"bar\":\"baz\"},\"wibble\":\"wobble\",\"tamil\":\"வணக்கம\"}"}
  end

  test "deserialize_cesr_json_payload deserializes" do
    our_map = %OrdMap{tuples: [{"v", "KERICAAJSONAAA-."},
                               {"foo", %OrdMap{tuples: [{"bar", "baz"}]}}, {"wibble", "wobble"}]}
    assert JsonUtils.deserialize_cesr_json_payload("{\"v\":\"KERICAAJSONAAA-.\",\"foo\":{\"bar\":\"baz\"},\"wibble\":\"wobble\"}")
      == {:ok, our_map}

    our_map_2 = %OrdMap{tuples: [{"v", "KERICAAJSONAABb."},
                                 {"foo", %OrdMap{tuples: [{"bar", "baz"}]}}, {"wibble", "wobble"},
     {"tamil", "வணக்கம"}]} # Added tamil so byte size is different than string.length
    assert JsonUtils.deserialize_cesr_json_payload("{\"v\":\"KERICAAJSONAABb.\",\"foo\":{\"bar\":\"baz\"},\"wibble\":\"wobble\",\"tamil\":\"வணக்கம\"}")
      == {:ok, our_map_2}
  end

  test "JSONUtils serialize serializes to an ordered map" do
    assert JsonUtils.serialize(%OrdMap{
      tuples: [{"foo", %OrdMap{tuples: [{"bar", "baz"}]}}, {"wibble", "wobble"}]
    }) == {:ok, "{\"foo\":{\"bar\":\"baz\"},\"wibble\":\"wobble\"}"}
  end

  test "JSONUtils serialize serializes to an empty map" do
    assert JsonUtils.serialize(%OrdMap{
      tuples: [{"foo", %OrdMap{tuples: []}}, {"wibble", "wobble"}]
    }) == {:ok, "{\"foo\":{},\"wibble\":\"wobble\"}"}
  end

  test "JSONUtils deserialize deserializes to an ordered map" do
    assert JsonUtils.deserialize("{\"foo\":{\"bar\":\"baz\"},\"wibble\":\"wobble\"}") ==
      {:ok, %OrdMap{
        tuples: [{"foo", %OrdMap{tuples: [{"bar", "baz"}]}}, {"wibble", "wobble"}]
      }}
  end

  test "JSONUtils deserialize deserializes empty map" do
    assert JsonUtils.deserialize("{}") == {:ok, %OrdMap{tuples: []}}
  end

  test "Keripy simple examples deserialize -> serialize -> deserialize" do
    Path.wildcard("test/kerilixir/example_payloads/simple/json/*") |> Enum.map(fn (example_payload) ->
      payload_binary = File.read!(example_payload)
      {:ok, deserialized_ordmap} = JsonUtils.deserialize_cesr_json_payload(payload_binary)
      {:ok, version_example} = Cesr.match_version(deserialized_ordmap["v"])
      {:ok, serialized_ordmap} = JsonUtils.serialize_cesr_json_payload(deserialized_ordmap, version_example)
      {:ok, deserialized_ordmap_2nd_rnd} = JsonUtils.deserialize_cesr_json_payload(serialized_ordmap)
      {:ok, version_reserialized} = Cesr.match_version(deserialized_ordmap_2nd_rnd["v"])
      assert deserialized_ordmap == deserialized_ordmap_2nd_rnd
      assert version_reserialized == version_example
      assert serialized_ordmap == payload_binary
    end)
  end

  # Jason Tests!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!11
  # Tests to ensure that Jason ordered representations match what we expectin the future
  test "Jason encode with a nested keyword list serializes to an ordered json map" do
    assert Jason.encode(Jason.OrderedObject.new([{"foo", "bar"},
      {"wibble", Jason.OrderedObject.new([{"zab", "zob"}, {"baz", "wobble"}])}]))
      == {:ok, "{\"foo\":\"bar\",\"wibble\":{\"zab\":\"zob\",\"baz\":\"wobble\"}}"}
  end

  test "Jason encode with unsorted keyword list serializes to an ordered json map" do
    assert Jason.encode(Jason.OrderedObject.new([{"wibble", "wobble"}, {"foo", "bar"}])) ==
      {:ok, "{\"wibble\":\"wobble\",\"foo\":\"bar\"}"}
  end

  test "Jason decode deserializes a json representation to an OrderedDict" do
    assert Jason.decode("{\"foo\":\"bar\",\"wibble\":\"wobble\"}", [objects: :ordered_objects]) ==
      {:ok, Jason.OrderedObject.new([{"foo", "bar"}, {"wibble", "wobble"}])}
  end

  test "Jason decode deserializes unsorted json representation to an OrderedDict" do
    assert Jason.decode("{\"wibble\":\"wobble\",\"foo\":\"bar\"}", [objects: :ordered_objects]) ==
      {:ok, Jason.OrderedObject.new([{"wibble", "wobble"}, {"foo", "bar"}])}
  end

  test "Jason encode with a keyword list serializes to an ordered json map" do
    assert Jason.encode(Jason.OrderedObject.new([{"foo", "bar"}, {"wibble", "wobble"}])) ==
      {:ok, "{\"foo\":\"bar\",\"wibble\":\"wobble\"}"}
  end

  test "Size calculated correctly for version string 1" do
    {:ok, vers_1} = Version_String_1.new(%{proto: :keri, major: 1, minor: 0, kind: :json, size: 0})
    our_map = %OrdMap{tuples: [{"foo", %OrdMap{tuples: [{"bar", "baz"}]}}, {"wibble", "wobble"}]}
    # same as first test above
    #assert JsonUtils.serialize_cesr_json_payload(our_map, vers_1) ==
    #  {:ok, "{\"v\":\"KERICAAJSONAAA-.\",\"foo\":{\"bar\":\"baz\"},\"wibble\":\"wobble\"}"}
    {:ok, serialized_map} = JsonUtils.serialize_cesr_json_payload(our_map, vers_1)
    {:ok, deserialized_map} = JsonUtils.deserialize_cesr_json_payload(serialized_map)
    {:ok, version_string} = Version_String_1.deserialize(OrdMap.get(deserialized_map, "v"))
    assert byte_size(serialized_map) == version_string.size
  end

  test "Size calculated correctly for version string 2" do
    {:ok, vers_2} = Version_String_2.new(%{proto: :keri, proto_major: 2, proto_minor: 0, genus_major: 2, genus_minor: 0, kind: :json, size: 0})
    our_map = %OrdMap{tuples: [{"foo", %OrdMap{tuples: [{"bar", "baz"}]}}, {"wibble", "wobble"}]}
    # same as first test above
    #assert JsonUtils.serialize_cesr_json_payload(our_map, vers_2) ==
    #  {:ok, "{\"v\":\"KERICAAJSONAAA-.\",\"foo\":{\"bar\":\"baz\"},\"wibble\":\"wobble\"}"}
    {:ok, serialized_map} = JsonUtils.serialize_cesr_json_payload(our_map, vers_2)
    {:ok, deserialized_map} = JsonUtils.deserialize_cesr_json_payload(serialized_map)
    {:ok, version_string} = Version_String_2.deserialize(OrdMap.get(deserialized_map, "v"))
    assert byte_size(serialized_map) == version_string.size
  end
end
