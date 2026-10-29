defmodule Cesr.Utility.JsonUtils do
  alias Cesr
  alias Cesr.CesrFieldMap.VersionString
  alias Cesr.Version_String_1
  alias Cesr.Version_String_2

  @spec serialize_cesr_json_payload(OrdMap.t()) :: {:ok, binary()} | {:error, any()}
  @doc """
    Serializes cesr payload to the stream as json.
      
    * For ordmaps with a Cesr Version String struct as the first element, the
      version string :kind must be the value :json. the size is recomputed based on
      the serialization length.
    * For ordmaps without a version string, the regular serialization is
      used (equivalent to this module's serialized_ordmap_to_json/1).
  """
  def serialize_cesr_json_payload(%OrdMap{tuples: [{"v", %Version_String_1{kind: :json}}|_]} = o) do 
    _serialize_cesr_json_payload(o)
  end
  def serialize_cesr_json_payload(%OrdMap{tuples: [{"v", %Version_String_2{kind: :json}}|_]} = o) do 
    _serialize_cesr_json_payload(o)
  end
  def serialize_cesr_json_payload(%OrdMap{tuples: [{"v", %Version_String_1{kind: _}}|_]}) do 
    {:error, :must_be_kind_json}
  end
  def serialize_cesr_json_payload(%OrdMap{tuples: [{"v", %Version_String_2{kind: _}}|_]}) do 
    {:error, :must_be_kind_json}
  end
  def serialize_cesr_json_payload(%OrdMap{} = o) do
    case check_ordmap(o) do
      {:error, _} = e ->  e
      :ok -> serialize_ordmap_to_json(o)
    end
  end
  def serialize_cesr_json_payload(_, _cesr_version), do: {:error, "We can only serialize top-level Ordmaps into cesr streams"}

  defp _serialize_cesr_json_payload(%OrdMap{tuples: [{"v", v}|_]} = o) do
    with {:ok, v_serialized} <- VersionString.serialize(v),
      {:ok, serialized} <- OrdMap.put(o, "v", v_serialized) |>
        serialize_ordmap_to_json(),
      {:ok, correct_version} <- VersionString.serialize(%{v | size: byte_size(serialized)})
    do
      versioned_o = OrdMap.put(o, "v", correct_version)
      case check_ordmap(versioned_o) do
        {:error, _} = e -> e
        :ok -> serialize_ordmap_to_json(versioned_o)
      end
    else
      e -> {:error, e}
    end
  end

  @doc """
  Deserializes cesr json payload from the stream
  """
  def deserialize_cesr_json_payload(potential_json_payload)
    when byte_size(potential_json_payload) < 25
  do
    {:error, "Not enough input to read version string"}
  end
  def deserialize_cesr_json_payload(<<potential_json_head::binary-size(25), _::binary>> = stream)
  do
    case Cesr.match_version(potential_json_head) do
      {:error, e} -> {:error, e}
      {:ok, version} -> read_off_size_json(stream, version)
    end
  end

  @doc """
  Helper method to serialize json to an OrdMap representation.

  Warning: Do not use unless you're prepared to deserialize version
  strings and check the validity of the Ordmap yourself if you're
  serializing to KERI or ACDC (or even TSP).  Use
  serialize_cesr_json_payload which deserializes and checks validity of
  ordmap for correctness.
  """
  def serialize_ordmap_to_json(ord_map) do
    Jason.encode(Jason.OrderedObject.new(ordmap_to_keyword_list(ord_map)))
  end

  @doc """
  Helper method to deserialize json to an OrdMap representation.

  Warning: Do not use unless you're prepared to deserialize version
  strings and check the validity of the Ordmap yourself if you're
  deserializing to KERI or ACDC (or even TSP).  Use
  desrialize_cesr_json_payload which deserializes and checks validity of
  ordmap for correctness.
  """
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
  defp deserialize_ordered_object(%Jason.OrderedObject{} = ordered_object) do
    Enum.map(ordered_object.values, &process_key_value/1) |> OrdMap.new
  end

  @spec process_key_value({any(), any()}) :: {any(), OrdMap.t()}
  defp process_key_value({key, value}) do
    case value do
      %Jason.OrderedObject{} -> {key, deserialize_ordered_object(value)}
      _ when is_list(value) -> {key, Enum.map(value, &process_val/1)}
      _ -> {key, value}
    end
  end

  defp process_val(value) do
    case value do
      _ when is_list(value) -> Enum.map(value, &process_val/1)
      %Jason.OrderedObject{} -> deserialize_ordered_object(value)
      _ -> value
    end
  end

  def check_ordmap(%OrdMap{} = o) do
    are_keys_valid? = try do
      OrdMap.keys(o) |> Enum.all?(fn k -> String.valid?(k) end)
    catch
      _ -> {:error, "Only valid strings can be keys"}
    end

    misc_version_strings? = OrdMap.values(o) |> 
    Enum.any?(fn %Version_String_1{} -> true
                 %Version_String_2{} -> true
                 _ -> false  
              end)
    case {are_keys_valid?, misc_version_strings?} do
      {true, false} -> :ok
      {true, true} -> {:error, "Version strings not allowed except first in a field map"}
      {false, _} -> {:error, "All keys must be strings"}
    end
  end

  defp read_off_size_json(stream, %{size: size})
    when byte_size(stream) < size
  do
    {:error, "Not enough bytes (#{size} bytes) in stream"}
  end
  defp read_off_size_json(stream, %{size: size} = version)
  do
    <<potential_json::binary-size(size), rest::binary>> = stream
    case deserialize(potential_json) do
      {:ok, json_ordmap} -> {:ok, OrdMap.put(json_ordmap, "v", version), rest}
      {:error, e} -> {:error, e}
    end
  end
end
