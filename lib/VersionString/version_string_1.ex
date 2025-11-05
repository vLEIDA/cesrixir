defmodule Cesr.Version_String_1 do
  alias Cesr.Version_String_1
  # https://trustoverip.github.io/tswg-cesr-specification/#legacy-version-string-field-format
  # proto: [KERI, ACDC]
  # major 0-16
  # minor 0-16
  # kind ['JSON', 'CBOR', 'MGPK', 'CESR']
  # size [0-16,777,216]

  @enforce_keys [:proto, :major, :minor, :kind, :size]
  defstruct [:proto, :major, :minor, :kind, :size]
  @type t :: %__MODULE__{
    proto: String.t() | atom(),
    major: integer(),
    minor: integer(),
    kind: String.t() | atom(),
    size: integer(),
  }

  @spec new(%{proto: String.t() | atom(), major: integer(), minor: integer(),
    kind: String.t() | atom(), size: integer()})
    :: {:ok, Version_String_1.t()} | {:error, String.t()}
  def new(map = %{proto: proto, major: major, minor: minor, kind: kind, size: size}) do
    if is_valid_proto(proto) and
       is_valid_major(major) and
       is_valid_minor(minor) and
       is_valid_kind(kind) and
       is_valid_size(size) do
      {:ok, struct(Version_String_1, map)}
    else
      {:error, "Failed to construct map:
                proto: #{proto}, valid: #{is_valid_proto(proto)} and
                major: #{major}, valid: #{is_valid_major(major)} and
                minor: #{minor}, valid: #{is_valid_minor(minor)} and
                kind: #{kind}, valid: #{is_valid_kind(kind)} and
                size: #{size}, valid: #{is_valid_size(size)}"}
    end
  end

  def new(_) do
    {:error, "Failed to construct map: missing arguments"}
  end

  @spec deserialize(String.t()) :: {:ok, Version_String_1.t()} | {:error, String.t()}
  @doc("If a valid KERI version string exists in the string passed to this function.
        We return a Version_String_1 struct. Else we return an error")
  def deserialize(potential_version_string) do
    with {:ok, named_captures} <- match_version1_regex(potential_version_string),
         {:ok, proto} <- get_valid_proto(named_captures[:proto]),
         {:ok, major} <- get_major_version(named_captures[:major]),
         {:ok, minor} <- get_minor_version(named_captures[:minor]),
         {:ok, kind} <- get_valid_kind(named_captures[:kind]),
         {:ok, size} <- get_size_value(named_captures[:size])
    do
      {:ok, %Version_String_1{proto: proto, major: major, minor: minor, kind: kind, size: size}}
    else
      {:error, err_msg} -> {:error, err_msg}
    end
  end

  @spec serialize(Version_String_1.t()) :: {:ok, String.t()} | {:error, any()}
  def serialize(version) do
    with {:ok, proto} <- serialize_valid_proto(version.proto),
         {:ok, major} <- get_valid_major(version.major),
         {:ok, minor} <- get_valid_minor(version.minor),
         {:ok, kind} <- serialize_valid_kind(version.kind),
         {:ok, size} <- get_valid_size(version.size)
    do
      {:ok, proto <> major <> minor <> kind <> size <> "_"}
    else
      {:error, err_msg} -> {:error, err_msg}
    end
  end

  @spec match_version1_regex(String.t())
    :: {:ok, %{proto: atom(), major: any(), minor: any(), kind: atom(), size: integer()}} | {:error, any()}
  defp match_version1_regex(potential_version_string) do
    version_1_regex = ~r/(?P<proto>[A-Z]{4})(?P<major>[0-9a-zA-Z-_]{1})(?P<minor>[0-9a-zA-Z-_]{1})(?P<kind>[A-Z]{4})(?P<size>[0-9a-zA-Z-_]{6})_/ # 17 char long
    if named_captures = Regex.named_captures(version_1_regex, potential_version_string) do
      named_captures |> Map.new(fn {k, v} -> {String.to_atom(k), v} end) |> Kernel.then(fn x -> {:ok, x} end)
    else
      {:error, "Version 1 Regular Expression didn't match against #{potential_version_string}"}
    end
  end

  # validity checks
  defp is_valid_proto(proto) when proto in [:acdc, :keri], do: true
  defp is_valid_proto(_proto), do: false
  defp is_valid_major(major) when is_integer(major) and major in 0..15, do: true
  defp is_valid_major(_major), do: false
  defp is_valid_minor(minor) when is_integer(minor) and minor in 0..15, do: true
  defp is_valid_minor(_minor), do: false
  defp is_valid_kind(kind) when kind in [:json, :cbor, :mgpk, :cesr], do: true
  defp is_valid_kind(_kind), do: false
  defp is_valid_size(size) when is_integer(size) and size in 0..16_777_215, do: true
  defp is_valid_size(_size), do: false

  # deserializes
  defp get_valid_proto("ACDC"), do: {:ok, :acdc}
  defp get_valid_proto("KERI"), do: {:ok, :keri}
  defp get_valid_proto(x), do: {:error, "Protocol #{x} not a valid protocol"}

  defp get_major_version(major_character) do
    {val, _} = Integer.parse(major_character, 16)
    {:ok, val}
  end

  defp get_minor_version(minor_value_chars) do
    {val, _} = Integer.parse(minor_value_chars, 16)
    {:ok, val}
  end

  defp get_size_value(size_characters) do
    {val, _} = Integer.parse(size_characters, 16)
    {:ok, val}
  end

  defp get_valid_kind("JSON"), do: {:ok, :json}
  defp get_valid_kind("CBOR"), do: {:ok, :cbor}
  defp get_valid_kind("MGPK"), do: {:ok, :mgpk}
  defp get_valid_kind(invalid_kind), do: {:error, "Kind #{invalid_kind} not a valid serialization"}

  # serializes
  defp serialize_valid_proto(:acdc), do: {:ok, "ACDC"}
  defp serialize_valid_proto(:keri), do: {:ok, "KERI"}
  defp serialize_valid_proto(_), do: {:error, "This error should never occur in serialize proto"}

  defp get_valid_major(value) when is_integer(value) and value in 0..15, do: {:ok, Integer.to_string(value, 16) |> String.downcase}
  defp get_valid_major(value), do: {:error, "Not a valid major value: #{value}"}

  defp get_valid_minor(value) when value in 0..15, do: {:ok, Integer.to_string(value, 16) |> String.downcase}
  defp get_valid_minor(value), do: {:error, "Value: #{value} not in range of base16 character"}

  defp serialize_valid_kind(:json), do: {:ok, "JSON"}
  defp serialize_valid_kind(:cbor), do: {:ok, "CBOR"}
  defp serialize_valid_kind(:mgpk), do: {:ok, "MGPK"}
  defp serialize_valid_kind(_), do: {:error, "This error should never occur in serialize proto"}

  defp get_valid_size(value) when is_integer(value) and value in 0..16_777_215, do: {:ok, String.pad_leading(Integer.to_string(value, 16) |> String.downcase, 6, "0")}
  defp get_valid_size(value), do: {:error, "Value #{value} not a valid size"}
end

defimpl Cesr.CesrFieldMap.VersionString, for: Cesr.Version_String_1 do
  def new(version_string_parameter_map), do: Cesr.Version_String_1.new(version_string_parameter_map)
  def serialize(version_string_struct), do: Cesr.Version_String_1.serialize(version_string_struct)
end

defimpl Jason.Encoder, for: Cesr.Version_String_1 do
  def encode(value, opts) do
    {:ok, serialized_version_string} = Cesr.Version_String_1.serialize(value)
    Jason.Encode.string(serialized_version_string, opts)
  end
end
