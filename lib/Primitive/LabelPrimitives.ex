# Similiarly to tags, lables don't really fit into the whole character schemes because they have
# different padding/payload characteristics than other code groups that they fall into
# in the spec.  This is conceptually difficult to tell from the spec alone, it
# requires reading the CESR spec in depth as well as the KERI spec and even
# then its not clear until you actually get to parsing  We'll implement them
# here instead.
#
# Labels in the keri protocol/genuses are essentially ways to put small binary payloads
# on the wire for simple text representations (in b64) by just mapping to a somewhat "readable"
# b64 string (rather than say encoding a text string that's readable into b64)
#
# Note: Unlike the Tag primitives we pad in the binary domain instead of the text domain so \
# instead of V_Aq we have VAAq -> 010101_00 0000_0000 0010_1010 where the first six bits are the code
# the next 10 bits are the padding and the final byte is the payload.  W doesn't have padding so
# you don't have to worry about it there but we include it here for clarity.


defmodule Cesr.Primitive.Generator.OneCharacterLabelPrimitives do
  @moduledoc "Generator for OneCharacterLabelPrimitives"
  def typeDescriptions, do: [
    # {moduleCode, shortName, longDescription, textLength, padding_bit_length}
    {"V", :Label1, "Label1 1 bytes for label lead size 1", 4, 10},
    {"W", :Label2, "Label2 2 bytes for label lead size 0", 4, 2} # two bits of padding to put b64 code on byte boundary
    ]
end

for {code, short_name, long_description, text_length, padding_bit_length} <-
    Cesr.Primitive.Generator.OneCharacterLabelPrimitives.typeDescriptions do
  module_name = Module.concat(Cesr.Primitive, "CD_#{code}_#{short_name}")
  {:ok, bits_of_code_rep} = Cesr.Utility.Base64Indicies.bits_of_b64_representation(code)
  bits_of_code_rep = Macro.escape(bits_of_code_rep)
  raw_size = ((text_length - String.length(code)) * 6) - padding_bit_length

  defmodule module_name do
    @enforce_keys [:code, :payload]
    defstruct [:code, :payload]

    def new(primitive_bytes) when is_bitstring(primitive_bytes) and bit_size(primitive_bytes) == unquote(raw_size) do
      {:ok, struct(__MODULE__, %{code: unquote(code), payload: primitive_bytes})}
    end
    def new(_primitive_bytes) do
      {:error, "#{unquote(Atom.to_string(__MODULE__))} size must be #{unquote(raw_size)} bits long when constructing"}
    end

    def from_b64(<<unquote(code), potential_payload::binary-size(unquote(text_length)-1), rest::binary>>) do
      {:ok, decoded_value} = Base.url_decode64(<<unquote(code), potential_payload::binary-size(unquote(text_length)-1)>>)
      <<unquote(bits_of_code_rep), _pad_char::size(unquote(padding_bit_length)), payload::bitstring>> = decoded_value
      {{:ok, struct(__MODULE__, %{code: unquote(code), payload: payload})}, rest}
    end

    def from_binary(<<unquote(bits_of_code_rep), _pad_char::size(unquote(padding_bit_length)), potential_payload::bitstring-size(unquote(raw_size)), rest::bitstring>>) do
      {{:ok, struct(__MODULE__, %{code: unquote(code), payload: <<potential_payload::bitstring>>})}, rest}
    end

    def to_b64(%__MODULE__{} = tag_primitive) do
      Base.url_encode64(<<unquote(bits_of_code_rep), 0::size(unquote(padding_bit_length)), tag_primitive.payload::bitstring>>)
    end

    def to_binary(%__MODULE__{} = tag_primitive) do
      <<unquote(bits_of_code_rep), 0::size(unquote(padding_bit_length)), tag_primitive.payload::bitstring>>
    end

    def properties do
      %{code: String.to_atom(unquote(code)), short_name: unquote(short_name), long_name: unquote(long_description), text_size: unquote(text_length)}
    end
  end

  # We implement our polymorphic protocol
  defimpl Cesr.CesrElement, for: module_name do
    def to_b64(cesr_element), do: unquote(module_name).to_b64(cesr_element)
    def to_binary(cesr_element), do: unquote(module_name).to_binary(cesr_element)
    def properties(_cesr_element), do: unquote(module_name).properties()
  end

  defimpl Jason.Encoder, for: module_name do
    def encode(value, opts), do: Jason.Encode.string(unquote(module_name).to_b64(value), opts)
  end
end
