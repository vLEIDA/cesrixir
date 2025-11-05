defmodule Cesr.Version_String_2 do
  import Cesr.Utility.Base64Indicies

  # From: https://trustoverip.github.io/tswg-cesr-specification/#version-string-field-format
  # proto: [KERI, ACDC]
    # major 0-63
    # minor 0-4095
  # (cesr genus): 
    # major 0-63
    # minor 0-4095
  # kind ['JSON', 'CBOR', 'MGPK', 'CESR']
  # size [0-16,777,215]

  @enforce_keys [:proto, :proto_major, :proto_minor, :genus_major, :genus_minor, :kind, :size]
  defstruct [:proto, :proto_major, :proto_minor, :genus_major, :genus_minor, :kind, :size]
  @type t :: %__MODULE__{
    proto: String.t() | atom(),
    proto_major: 0..63,
    proto_minor: 0..4095,
    genus_major: 0..63,
    genus_minor: 0..4095,
    kind: String.t() | atom(),
    size: 0..16_777_215
  }

  @spec new(%{proto: String.t() | atom(), proto_major: integer(), proto_minor: integer(),
              genus_major: integer(), genus_minor: integer(),
              kind: String.t() | atom(), size: integer()}) :: {:ok, __MODULE__.t()} | {:error, String.t()}
  def new(%{proto: proto, proto_major: proto_major, proto_minor: proto_minor, 
            genus_major: genus_major, genus_minor: genus_minor, 
            kind: kind, size: size} = map)
  when proto in [:keri, :acdc] and
    proto_major in 0..63 and proto_minor in 0..4095 and
    genus_major in 0..63 and genus_minor in 0..4095 and
    kind in [:json, :cbor, :mgpk, :cesr] and
    size in 0..16_777_215
  do
    {:ok, struct(__MODULE__, map)}
  end
  def new(%{proto: proto, proto_major: proto_major, proto_minor: proto_minor, 
            genus_major: genus_major, genus_minor: genus_minor, 
            kind: kind, size: size}) 
  do
    is_valid_proto? = proto in [:keri, :acdc]
    is_valid_proto_major? = proto_major in 0..63 
    is_valid_proto_minor? = proto_minor in 0..4095
    is_valid_genus_major? = genus_major in 0..63 
    is_valid_genus_minor? = genus_minor in 0..4095
    is_valid_kind? = kind in [:json, :cbor, :mgpk, :cesr] 
    is_valid_size? = size in 0..16_777_215

    {:error, "Failed to construct map:
              proto: #{proto}, valid: #{is_valid_proto?}
              proto_major: #{proto_major}, valid: #{is_valid_proto_major?}
              proto_minor: #{proto_minor}, valid: #{is_valid_proto_minor?}
              genus_major: #{genus_major}, valid: #{is_valid_genus_major?}
              genus_minor: #{genus_minor}, valid: #{is_valid_genus_minor?}
              kind: #{kind}, valid: #{is_valid_kind?}
              size: #{size}, valid: #{is_valid_size?}"}
  end
  def new(_) do
    {:error, "Failed to construct Version String: missing arguments"}
  end

  def new_latest() do
    new(%{proto: :keri, proto_major: 2, proto_minor: 0,
          genus_major: 2, genus_minor: 0, kind: :json, size: 0})
  end

  @spec deserialize(String.t()) :: {:ok, __MODULE__.t()} | {:error, String.t()}
  def deserialize(<<proto::binary-size(4), 
                    proto_major::binary-size(1), proto_minor::binary-size(2),
                    genus_major::binary-size(1), genus_minor::binary-size(2),
                    kind::binary-size(4), size::binary-size(4), ".", _::binary>>)
  do
    with {:ok, pro} <- deserialize_to_atom(proto),
         {:ok, pmaj} <- deserialize_value_in_b64_index_scheme(proto_major),
         {:ok, pmin} <- deserialize_value_in_b64_index_scheme(proto_minor),
         {:ok, gmaj} <- deserialize_value_in_b64_index_scheme(genus_major),
         {:ok, gmin} <- deserialize_value_in_b64_index_scheme(genus_minor),
         {:ok, kd} <- deserialize_to_atom(kind),
         {:ok, sz} <- deserialize_value_in_b64_index_scheme(size)
    do
      map_for_constructor = %{proto: pro, proto_major: pmaj, proto_minor: pmin,
        genus_major: gmaj, genus_minor: gmin, kind: kd, size: sz}

      case map_for_constructor do
        %{proto: proto, proto_major: proto_major, proto_minor: proto_minor,
          genus_major: genus_major, genus_minor: genus_minor, kind: kind, size: size} = map_for_constructor 
            when proto in [:keri, :acdc] and
                 proto_major in 0..63 and proto_minor in 0..4095 and
                 genus_major in 0..63 and genus_minor in 0..4095 and
                 kind in [:json, :cbor, :mgpk, :cesr] and
                 size in 0..16_777_215 -> {:ok, struct(__MODULE__, map_for_constructor)}
        invalid_map_for_constructor when is_map(invalid_map_for_constructor) ->
          {:error, "Failed to deserialize: #{inspect(invalid_map_for_constructor)}"}
      end
    else
      {:error, err_msg} -> {:error, err_msg}
    end
  end
  def deserialize(<<_::binary-size(1), next_try::binary>>) 
    when byte_size(next_try) >= 17
  do
    deserialize(next_try)
  end
  def deserialize(_), do: {:error, "Failed to deserialize"}

  @spec serialize(__MODULE__.t()) :: {:ok, String.t()} | {:error, any()}
  def serialize(%__MODULE__{} = version) do
    with proto <- Atom.to_string(version.proto) |> String.upcase,
         {:ok, proto_major} <- serialize_value_in_b64_index_scheme(version.proto_major, 1),
         {:ok, proto_minor} <- serialize_value_in_b64_index_scheme(version.proto_minor, 2),
         {:ok, genus_major} <- serialize_value_in_b64_index_scheme(version.genus_major, 1),
         {:ok, genus_minor} <- serialize_value_in_b64_index_scheme(version.genus_minor, 2),
         kind <- Atom.to_string(version.kind) |> String.upcase,
         {:ok, size} <- serialize_value_in_b64_index_scheme(version.size, 4)
    do
      {:ok, Enum.join([proto, proto_major, proto_minor, genus_major, genus_minor, kind, size, "."])}
    else
      {:error, err_msg} -> {:error, err_msg}
    end
  end

  defp deserialize_to_atom(potential_atom) do
    try do
      {:ok, String.downcase(potential_atom) |> String.to_existing_atom()}
    rescue
      ArgumentError -> {:error, "Potential atom: #{potential_atom} not valid in kerilixir"}
    end
  end
end

defimpl Cesr.CesrFieldMap.VersionString, for: Cesr.Version_String_2 do
  def new(version_string_parameter_map), do: Cesr.Version_String_2.new(version_string_parameter_map)
  def serialize(version_string_struct), do: Cesr.Version_String_2.serialize(version_string_struct)
end

defimpl Jason.Encoder, for: Cesr.Version_String_2 do
  def encode(value, opts) do
    {:ok, serialized_version_string} = Cesr.Version_String_2.serialize(value)
    Jason.Encode.string(serialized_version_string, opts)
  end
end
