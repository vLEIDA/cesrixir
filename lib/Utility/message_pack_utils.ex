defmodule Cesr.Utility.MessagePackUtils do
  @moduledoc """
  Message Pack utilities for cesr payloads.
  """

  alias Cesr.CesrFieldMap.VersionString

  @spec serialize_cesr_mgpk_payload(OrdMap.t(), VersionString.t()) ::
    {:ok, binary()} | {:error, any()}
  def serialize_cesr_mgpk_payload(%OrdMap{} = ordered_map_payload, cesr_version) do
    # FOR CESR
    # 1. We insert dummy version string of length of scheme into map
    # 2. mpgk.serialize with order of fields
    # 3. Construct version string of actual size of construct
    # 4. Put that version string in the map
    # 5. Serialize into binary and return

    with :ok <- check_kind(cesr_version),
      dummy_version <- %{cesr_version | size: 0},
      {:ok, dummy_version_string} <- VersionString.serialize(dummy_version),
      # we do it this weird way so that v is always inserted first
      payload_with_dummy_version <- OrdMap.new([{"v", dummy_version_string}]
        ++ OrdMap.delete(ordered_map_payload, "v").tuples),
      {:ok, dummy_payload_string} <- serialize_ordmap_to_mgpk(payload_with_dummy_version),
      correct_version <- %{cesr_version | size: byte_size(dummy_payload_string)},
      {:ok, correct_version_string} <- VersionString.serialize(correct_version)
    do
      pre_serialized_ordmap = OrdMap.new([{"v", correct_version_string}]
                                ++ OrdMap.delete(payload_with_dummy_version, "v").tuples)
      serialize_ordmap_to_mgpk(pre_serialized_ordmap)
    else
      {:error, :must_be_kind_mgpk} -> {:error, :must_be_kind_mgpk}
      e -> dbg(e)
    end
  end
  def serialize_cesr_mgpk_payload(_, _cesr_version), do: {:error, "We can only serialize top-level Ordmaps into cesr streams"}

  @spec deserialize_cesr_mgpk_payload(<<>>) :: {:ok, OrdMap.t()} | {:error, any()}
  def deserialize_cesr_mgpk_payload(potential_message_pack_cesr_payload) do
    # Note(CAL): Not sure if jsx or jiffy is better.  They are k,v associative array representations
    # of the map that have the same order as the serialization as far as we can tell.  We did
    # just eyeball it though, not 100% if that's a contract
    case :msgpack.unpack(potential_message_pack_cesr_payload, [map_format: :jsx, unpack_str: :as_binary]) do
      {:ok, property_list} -> {:ok, OrdMap.new(deserialize_property_list(property_list))}
      {:error, err_msg} -> {:error, "Error in MsgPack decoding: #{err_msg}"}
    end
  end

  @spec serialize_ordmap_to_mgpk(OrdMap.t()) :: 
    {:ok, binary()} | {:error, any()}
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

  defp check_kind(%{kind: :mgpk}), do: :ok
  defp check_kind(%{kind: _}), do: {:error, :must_be_kind_mgpk}
end
