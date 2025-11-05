defmodule Cesr.Primitive.DummySaidDigest do
  alias Cesr.Primitive.DummySaidDigest

  defstruct [:size, dummy_character: "#"]
  @type t :: %__MODULE__{size: pos_integer(), dummy_character: binary()}

  def new(size) when is_integer(size) and size >= 1 do
    %DummySaidDigest{size: size}
  end

  # Note: We call it "to_b64" but the default character "#" obviously isn't b64
  # This is by design in the spec.  Mostly we're just fitting it into the real
  # digest interface
  def to_b64(%DummySaidDigest{size: size, dummy_character: dummy_character}) do
    String.duplicate(dummy_character, size)
  end

  def to_binary(%DummySaidDigest{size: size, dummy_character: dummy_character}) do
    String.duplicate(dummy_character, size)
  end

  def properties(%DummySaidDigest{size: size}), do: %{code: String.to_atom("#"), short_name: :dummy, long_name: "Dummy",
                                                      text_size: size}
end

defimpl Cesr.CesrElement, for: Cesr.Primitive.DummySaidDigest do
  alias Cesr.Primitive.DummySaidDigest

  def to_b64(cesr_element), do: DummySaidDigest.to_b64(cesr_element)
  def to_binary(cesr_element), do: DummySaidDigest.to_binary(cesr_element)
  def properties(cesr_element), do: DummySaidDigest.properties(cesr_element)
end
