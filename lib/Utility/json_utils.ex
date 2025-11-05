defmodule Cesr.Utility.JsonUtils do
  alias Cesr.CesrFieldMap.VersionString

  @spec serialize_cesr_json_payload(OrdMap.t(), VersionString.t())
    :: {:ok, binary()} | {:error, any()}
  @doc("Serializes cesr json payload to the stream")
  def serialize_cesr_json_payload(%OrdMap{} = ordered_map_payload, cesr_version) do
    # FOR CESR
    # 1. We insert dummy version string of length of scheme into map
    # 2. json.serialize with order of fields (minified)
    # 3. Construct version string of actual size
    # 4. Put that version string in the map
    # 5. Serialize (minified) and return

    with :ok <- check_kind(cesr_version),
      dummy_version <- %{cesr_version | size: 0},
      {:ok, dummy_version_string} <- VersionString.serialize(dummy_version),
      # we do it this weird way so that v is always inserted first
      payload_with_dummy_version <- OrdMap.new([{"v", dummy_version_string}]
        ++ OrdMap.delete(ordered_map_payload, "v").tuples),
      {:ok, dummy_payload_string} <- serialize(payload_with_dummy_version),
      correct_version <- %{cesr_version | size: byte_size(dummy_payload_string)},
      {:ok, correct_version_string} <- VersionString.serialize(correct_version)
    do
      serialize(OrdMap.new([{"v", correct_version_string}]
        ++ OrdMap.delete(payload_with_dummy_version, "v").tuples))
    else 
      {:error, :must_be_kind_json} -> {:error, :must_be_kind_json}
      e -> dbg(e)
    end
  end
  def serialize_cesr_json_payload(_, _cesr_version), do: {:error, "We can only serialize top-level Ordmaps into cesr streams"}

  @doc """
  Deserializes cesr json payload from the stream
  """
  def deserialize_cesr_json_payload(potential_json_payload) do
    deserialize(potential_json_payload)
  end

  def serialize(ord_map) do
    Jason.encode(Jason.OrderedObject.new(ordmap_to_keyword_list(ord_map)))
  end

  def deserialize(potential_json_serialization) do
    case Jason.decode(potential_json_serialization, [objects: :ordered_objects]) do
      {:ok, ordered_jason_obj} -> {:ok, OrdMap.new(deserialize_ordered_object(ordered_jason_obj))}
      {:error, err_msg} -> {:error, "Error in JSON decoding: #{err_msg}"}
    end
  end

  @spec ordmap_to_keyword_list(OrdMap.t()) :: any()
  defp ordmap_to_keyword_list(ordered_object = %OrdMap{}) do
    Enum.map(ordered_object.tuples, &convert_tuple/1)
  end

  @spec convert_tuple({any(), any()}) :: {any(), any()}
  defp convert_tuple({key, value}) do
    case value do
      %OrdMap{} -> {key, Jason.OrderedObject.new(ordmap_to_keyword_list(value))}
      [%OrdMap{} | _] -> {key, Enum.map(value, &Jason.OrderedObject.new(ordmap_to_keyword_list(&1)))}
      _ -> {key, value}
    end
  end

  @spec deserialize_ordered_object(any()) :: OrdMap.t()
  defp deserialize_ordered_object(ordered_object) do
    Enum.map(ordered_object.values, &deserialize_tuple/1) |> OrdMap.new
  end

  @spec deserialize_tuple({any(), any()}) :: {any(), OrdMap.t()}
  defp deserialize_tuple({key, value}) do
    case value do
      %Jason.OrderedObject{} -> {key, deserialize_ordered_object(value)}
      _ -> {key, value}
    end
  end

  defp check_kind(%{kind: :json}), do: :ok
  defp check_kind(%{kind: _}), do: {:error, :must_be_kind_json}
end
