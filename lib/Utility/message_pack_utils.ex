defmodule Cesr.Utility.MessagePackUtils do
  @moduledoc """
  Message Pack utilities for cesr payloads.

  Note: Most msgpack encoder/decoders will create different sized entries
  for different numbers of keys.  So normally, if people pick the
  simplest representation for their implementations there will be no
  problem and any msgpack fieldmap will round trip.  
  
  HOWEVER, the spec doesn't forbid putting in smaller numbers of entries into bigger maps.
  ie) we can create a 16 or 32 fieldmap per the spec with only 15
  entries.  This makes roundtripping a mgpk fieldmap in KERI problematic
  should we ever run into an implementation that does this.  I'm not sure
  what the python messagepack library does today and this erlang library
  doesn't allow picking which size of fieldmap you create but I'm leaving
  this note here for future generations.
  """

  alias Cesr.CesrFieldMap.VersionString
  alias Cesr.Utility.JsonUtils
  alias Cesr.Version_String_1
  alias Cesr.Version_String_2

  @spec serialize_cesr_mgpk_payload(OrdMap.t()) ::
    {:ok, binary()} | {:error, any()}
  @doc """
    Serializes cesr payload to the stream as mgpk.
      
    * For ordmaps with a Cesr Version String struct as the first element, the
      version string :kind must be the value :mgpk. the size is recomputed based on
      the serialization length.
    * For ordmaps without a version string, the regular serialization is
      used (equivalent to this module's serialized_ordmap_to_mgpk/1).
  """
  def serialize_cesr_mgpk_payload(%OrdMap{tuples: [{"v", %Version_String_1{kind: :mgpk}}|_]} = o) do 
      _serialize_cesr_mgpk_payload(o)
  end
  def serialize_cesr_mgpk_payload(%OrdMap{tuples: [{"v", %Version_String_2{kind: :mgpk}}|_]} = o) do 
      _serialize_cesr_mgpk_payload(o)
  end
  def serialize_cesr_mgpk_payload(%OrdMap{tuples: [{"v", %Version_String_1{kind: _}}|_]}) do 
      {:error, :must_be_kind_mgpk}
  end
  def serialize_cesr_mgpk_payload(%OrdMap{tuples: [{"v", %Version_String_2{kind: _}}|_]}) do 
      {:error, :must_be_kind_mgpk}
  end
  def serialize_cesr_mgpk_payload(%OrdMap{} = o) do
    case JsonUtils.check_ordmap(o) do
      {:error, _} = e ->  e
      :ok -> serialize_ordmap_to_mgpk(o)
    end
  end
  def serialize_cesr_mgpk_payload(_, _cesr_version), do: {:error, "We can only serialize top-level Ordmaps into cesr streams"}

  defp _serialize_cesr_mgpk_payload(%OrdMap{tuples: [{"v", v}|_]} = o) do
    with {:ok, v_serialized} <- VersionString.serialize(v),
      {:ok, serialized} <- OrdMap.put(o, "v", v_serialized) |>
        serialize_ordmap_to_mgpk(),
      {:ok, correct_version} <- VersionString.serialize(%{v | size: byte_size(serialized)})
    do
      versioned_o = OrdMap.put(o, "v", correct_version)
      case JsonUtils.check_ordmap(versioned_o) do
        {:error, _} = e -> e
        :ok -> serialize_ordmap_to_mgpk(versioned_o)
      end
    else
      e -> {:error, e}
    end
  end

  @spec deserialize_cesr_mgpk_payload(binary()) :: 
    {:ok, OrdMap.t(), binary()} | {:error, any()}
  @doc """
  Deserializes cesr mgpk payload from the stream
  """
  def deserialize_cesr_mgpk_payload(potential_mgpk_payload)
    when byte_size(potential_mgpk_payload) < 25
  do
    {:error, "Not enough input to read version string"}
  end
  def deserialize_cesr_mgpk_payload(<<potential_mgpk_head::binary-size(25), _::binary>> = stream)
  do
    case Cesr.match_version(potential_mgpk_head) do
      {:error, e} -> {:error, e}
      {:ok, version} -> read_off_size_mgpk(stream, version)
    end
  end

  @doc """
  Helper method to deserialize json to an OrdMap representation.

  Warning: Do not use unless you're prepared to deserialize version
  strings and check the validity of the Ordmap yourself if you're
  deserializing to KERI or ACDC (or even TSP).  Use
  desrialize_cesr_json_payload which deserializes and checks validity of
  ordmap for correctness.
  """
  def deserialize(potential_msgpack_cesr_payload) do
    # Note(CAL): Not sure if jsx or jiffy is better.  They are k,v associative array representations
    # of the map that have the same order as the serialization as far as we can tell.  We did
    # just eyeball it though, not 100% if that's a contract
    case :msgpack.unpack(potential_msgpack_cesr_payload, [map_format: :jsx, unpack_str: :as_binary]) do
      {:ok, property_list} -> {:ok, OrdMap.new(deserialize_property_list(property_list))}
      {:error, err_msg} -> {:error, "Error in MsgPack decoding: #{err_msg}"}
    end
  end

  @spec serialize_ordmap_to_mgpk(OrdMap.t()) :: 
    {:ok, binary()} | {:error, any()}
  @doc """
  Helper method to serialize mgpk to an OrdMap representation.

  Warning: Do not use unless you're prepared to deserialize version
  strings and check the validity of the Ordmap yourself if you're
  serializing to KERI or ACDC (or even TSP).  Use
  serialize_cesr_mgpk_payload which deserializes and checks validity of
  ordmap for correctness.
  """
  def serialize_ordmap_to_mgpk(%OrdMap{} = ord_map) do
    prop_list = ordmap_to_jsx_property_list(ord_map)
    case :msgpack.pack(prop_list, [map_format: :jsx, pack_str: :from_binary]) do
      packed_data when is_binary(packed_data) -> {:ok, packed_data}
      {:error, err_msg} -> {:error, err_msg}
    end
  end

  defp deserialize_property_list(property_list = [{_k, _v} | _tail]) do
    Enum.map(property_list, &deserialize_property_list/1) |> OrdMap.new
  end
  defp deserialize_property_list({k, v}), do: {k, deserialize_property_list(v)}
  defp deserialize_property_list(value), do: value

  @spec ordmap_to_jsx_property_list(OrdMap.t()) :: list()
  defp ordmap_to_jsx_property_list(ordered_object) do
    Enum.map(ordered_object.tuples, &convert_tuple/1)
  end

  @spec convert_tuple({any(), any()}) :: {any(), any()}
  defp convert_tuple({key, value}) do
    case value do
      %OrdMap{} -> {key, ordmap_to_jsx_property_list(value)}
      [%OrdMap{}|_] -> {key, Enum.map(value, &ordmap_to_jsx_property_list(&1))}
      _ -> {key, value}
    end
  end

  defp read_off_size_mgpk(stream, %{size: size})
    when byte_size(stream) < size
  do
    {:error, "Not enough bytes (#{size} bytes) in stream"}
  end
  defp read_off_size_mgpk(stream, %{size: size} = version)
  do
    <<potential_mgpk::binary-size(size), rest::binary>> = stream
    case deserialize(potential_mgpk) do
      {:ok, mgpk_ordmap} -> {:ok, OrdMap.put(mgpk_ordmap, "v", version), rest}
      {:error, e} -> {:error, e}
    end
  end
end
