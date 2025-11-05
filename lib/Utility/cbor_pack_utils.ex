defmodule Cesr.Utility.CBORUtils do
  @moduledoc """
  CBOR utilities for cesr fieldmap payloads.
  """

  alias Cesr.CesrFieldMap.VersionString

  @spec serialize_cesr_cbor_payload(OrdMap.t(), VersionString.t()) ::
    {:ok, binary()} | {:error, any()}
  def serialize_cesr_cbor_payload(%OrdMap{} = ordered_map_payload, cesr_version) do
    # FOR CESR
    # 1. We insert dummy version string of length of scheme into map
    # 2. cbor.encode with order of fields
    # 3. Construct version string of actual size of construct
    # 4. Put that version string in the map
    # 5. Serialize into binary and return

    with :ok <- check_kind(cesr_version),
      dummy_version <- %{cesr_version | size: 0},
      {:ok, dummy_version_string} <- VersionString.serialize(dummy_version),
      # we do it this weird way so that v is always inserted first
      payload_with_dummy_version <- OrdMap.new([{"v", dummy_version_string}]
        ++ OrdMap.delete(ordered_map_payload, "v").tuples),
      {:ok, dummy_payload_string} <- serialize_ordmap_to_cbor(payload_with_dummy_version),
      correct_version <- %{cesr_version | size: byte_size(dummy_payload_string)},
      {:ok, correct_version_string} <- VersionString.serialize(correct_version)
    do
      pre_serialized_ordmap = OrdMap.new([{"v", correct_version_string}]
                                ++ OrdMap.delete(payload_with_dummy_version, "v").tuples)
      serialize_ordmap_to_cbor(pre_serialized_ordmap)
    else
      {:error, :must_be_kind_cbor} -> {:error, :must_be_kind_cbor}
      e -> dbg(e)
    end
  end
  def serialize_cesr_cbor_payload(_, _cesr_version), do: {:error, "We can only serialize top-level Ordmaps into cesr streams"}

  @spec deserialize_cesr_cbor_payload(binary()) :: {:ok, OrdMap.t()} | {:error, any()}
  def deserialize_cesr_cbor_payload(potential_cbor_cesr_payload) do
    case CBOR.decode(potential_cbor_cesr_payload, :ordered) do
      # We should never have a rest because the CESR stream parser should be dealing with this
      # ie) we need to error out on CBOR that has been concatenated together naively not in the CESR way.
      {:ok, %OrdMap{} = o, ""} -> {:ok, o}
      {:error, err_msg} -> {:error, "Error in CBOR decoding: #{err_msg}"}
    end
  end

  @spec serialize_ordmap_to_cbor(OrdMap.t()) :: {:ok, binary()}
  def serialize_ordmap_to_cbor(%OrdMap{} = ord_map), do: {:ok, CBOR.encode(ord_map)}

  defp check_kind(%{kind: :cbor}), do: :ok
  defp check_kind(%{kind: _}), do: {:error, :must_be_kind_cbor}
end
