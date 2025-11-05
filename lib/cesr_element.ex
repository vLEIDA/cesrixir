defprotocol Cesr.CesrElement do
  @doc """
  Provides polymorphism to all our CesrElements so that we can
  serialize to a wire representation without knowing which
  particular module to call on our struct
  """
  @spec to_b64(struct()) :: String.t()
  def to_b64(cesr_element)
  @spec to_binary(struct()) :: nonempty_binary()
  def to_binary(cesr_element)
  @spec properties(struct() | bitstring()) :: %{code: atom() | String.t(), short_name: atom(), long_name: String.t(), text_size: non_neg_integer()}
  def properties(_cesr_element)
end
