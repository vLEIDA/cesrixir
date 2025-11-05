defprotocol Cesr.CesrFieldMap.VersionString do
  @type version_string :: Cesr.CodeTable.KeriElementGroupings.version_string()

  @doc """
  FieldMap polymorphism for new() constructor which validates that we're creating a struct with real values
  """
  @spec new(%{proto: String.t() | atom(),
    major: integer(),
    minor: integer(),
    kind: String.t() | atom(),
    size: integer()} |
    %{proto: String.t() | atom(), 
      proto_major: integer(), proto_minor: integer(), 
      genus_major: integer(), genus_minor: integer(), 
      kind: String.t() | atom(), size: integer()})
    :: {:ok, version_string()} | {:error, String.t()}
  def new(cesr_element)
  @spec serialize(t()) :: {:ok, binary()} | {:error, term()}
  def serialize(cesr_version_string)
end
