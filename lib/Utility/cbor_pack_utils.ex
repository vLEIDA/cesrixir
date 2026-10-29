defmodule Cesr.Utility.CBORUtils do
  @moduledoc """
  CBOR utilities for cesr fieldmap payloads.
  """

  alias Cesr
  alias Cesr.CesrFieldMap.VersionString
  alias Cesr.Version_String_1
  alias Cesr.Version_String_2
  alias Cesr.Utility.JsonUtils

  @spec serialize_cesr_cbor_payload(OrdMap.t()) ::
    {:ok, binary()} | {:error, any()}
  @doc """
    Serializes cesr payload to the stream as cbor.
      
    * For ordmaps with a Cesr Version String struct as the first element, the
      version string :kind must be the value :cbor. the size is recomputed based on
      the serialization length.
    * For ordmaps without a version string, the regular serialization is
      used (equivalent to this module's serialized_ordmap_to_cbor/1).
  """
  def serialize_cesr_cbor_payload(%OrdMap{tuples: [{"v", %Version_String_1{kind: :cbor}}|_]} = o) do 
    _serialize_cesr_cbor_payload(o)
  end
  def serialize_cesr_cbor_payload(%OrdMap{tuples: [{"v", %Version_String_2{kind: :cbor}}|_]} = o) do 
    _serialize_cesr_cbor_payload(o)
  end
  def serialize_cesr_cbor_payload(%OrdMap{tuples: [{"v", %Version_String_1{kind: _}}|_]}) do 
    {:error, :must_be_kind_cbor}
  end
  def serialize_cesr_cbor_payload(%OrdMap{tuples: [{"v", %Version_String_2{kind: _}}|_]}) do 
    {:error, :must_be_kind_cbor}
  end
  def serialize_cesr_cbor_payload(%OrdMap{} = o) do
    case JsonUtils.check_ordmap(o) do
      {:error, _} = e ->  e
      :ok -> serialize_ordmap_to_cbor(o)
    end
  end
  def serialize_cesr_cbor_payload(_, _cesr_version), do: {:error, "We can only serialize top-level Ordmaps into cesr streams"}

  defp _serialize_cesr_cbor_payload(%OrdMap{tuples: [{"v", v}|_]} = o) do
    with {:ok, v_serialized} <- VersionString.serialize(v),
      {:ok, serialized} <- OrdMap.put(o, "v", v_serialized) |>
        serialize_ordmap_to_cbor(),
      {:ok, correct_version} <- VersionString.serialize(%{v | size: byte_size(serialized)})
    do
      versioned_o = OrdMap.put(o, "v", correct_version)
      case JsonUtils.check_ordmap(versioned_o) do
        {:error, _} = e -> e
        :ok -> serialize_ordmap_to_cbor(versioned_o)
      end
    else
      e -> {:error, e}
    end
  end

  @doc """
  Deserializes cesr cbor payload from the stream
  """
  def deserialize_cesr_cbor_payload(potential_cbor_payload)
    when byte_size(potential_cbor_payload) < 25
  do
    {:error, "Not enough input to read version string"}
  end
  def deserialize_cesr_cbor_payload(<<potential_cbor_head::binary-size(25), _::binary>> = stream)
  do
    case Cesr.match_version(potential_cbor_head) do
      {:error, e} -> {:error, e}
      {:ok, version} -> read_off_size_cbor(stream, version)
    end
  end

  @spec deserialize(binary()) :: {:ok, OrdMap.t()} | {:error, any()}
  def deserialize(potential_cbor_cesr_payload) do
    case CBOR.decode(potential_cbor_cesr_payload, :ordered) do
      # We should never have a rest because the CESR stream parser should be dealing with this
      # ie) we need to error out on CBOR that has been concatenated together naively not in the CESR way.
      {:ok, %OrdMap{} = o, ""} -> {:ok, o}
      {:error, err_msg} -> {:error, "Error in CBOR decoding: #{err_msg}"}
    end
  end

  @spec serialize_ordmap_to_cbor(OrdMap.t()) :: {:ok, binary()}
  def serialize_ordmap_to_cbor(%OrdMap{} = ord_map), do: {:ok, CBOR.encode(ord_map)}

  defp read_off_size_cbor(stream, %{size: size})
    when byte_size(stream) < size
  do
    {:error, "Not enough bytes (#{size} bytes) in stream"}
  end
  defp read_off_size_cbor(stream, %{size: size} = version)
  do
    <<potential_cbor::binary-size(size), rest::binary>> = stream
    case deserialize(potential_cbor) do
      {:ok, cbor_ordmap} -> {:ok, OrdMap.put(cbor_ordmap, "v", version), rest}
      {:error, e} -> {:error, e}
    end
  end
end
