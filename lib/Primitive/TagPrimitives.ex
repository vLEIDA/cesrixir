# Tags don't really fit into the whole character schemes because they have
# different padding/payload characteristics than other code groups that they fall into
# in the spec.  This is conceptually difficult to tell from the spec alone, it
# requires reading the CESR spec in depth as well as the KERI spec and even
# then its not clear until you actually get to parsing  We'll implement them
# here instead.
#
# Keripy at this moment also doesn't set a "raw" property for
# these (so you'll miss them in the test vectors) even though they descend from
# the Matter class.  Not sure what this is about but its probably because these
# values are mapped statically somewhere else in the codebase we just didn't
# bother to find yet.
#
# Tags in the keri protocol/genuses are essentially ways to put small binary payloads
# on the wire for readable text representations (in b64) by just mapping to a readable
# b64 string (rather than say encoding a text string that's readable into b64)
#
# ie) Text domain: "Xrot" -> Binary domain: "\x5e\xba\x2d"
#     Text domain: "OJ_a" -> Binary domain: "\xd0\x9f\xda"

defmodule Cesr.Primitive.Generator.OneCharacterTagPrimitives do
  @moduledoc "Generator for OneCharacterTagPrimitives"
  def typeDescriptions, do: [
    # {moduleCode, shortName, longDescription, textLength, pad_char_length}
    {"X", :Tag3, "Tag3  3 B64 encoded chars for special values", 4, 0},
    {"Y", :Tag7, "Tag7  7 B64 encoded chars for special values", 8, 0},
    {"Z", :Tag11, "Tag11 11 B64 encoded chars for special values", 12, 0}
    ]
end

defmodule Cesr.Primitive.Generator.TwoCharacterTagPrimitives do
  @moduledoc "Generator for TwoCharacterTagPrimitives"
  def typeDescriptions, do: [
    # {moduleCode, shortName, longDescription, textLength, pad_char_length}
    {"0J", :Tag1_1_B64_encoded_char,    "Tag1 1 B64 encoded char + 1 prepad for special values",         4, 1},
    {"0K", :Tag2_2_B64_encoded_chars,   "Tag2 2 B64 encoded chars for for special values",	             4, 0},
    {"0L", :Tag5_5_B64_encoded_chars,   "Tag5 5 B64 encoded chars + 1 prepad for for special values",    8, 1},
    {"0M", :Tag6_6_B64_encoded_chars,   "Tag6 6 B64 encoded chars for for special values",	             8, 0},
    {"0N", :Tag9_9_B64_encoded_chars,   "Tag9 9 B64 encoded chars + 1 prepad for special values",       12, 1},
    {"0O", :Tag10_10_B64_encoded_chars, "Tag10 10 B64 encoded chars for special values",	            12, 0}
    ]
    # Like the malicious fae from which he springs, the submarine scientist has
    # put these codes into the CESR spec like little riddles for us to solve.
    # They make no sense in the table as written for the other codes.  For
    # example GramHeadNeck at this moment in the table is a code with 2
    # characters for the code 22 characters for the count yet somehow equals
    # 32 characters total...
    #
    # I have no clue wtf these mean and its not specified anywhere other than
    # here below the tags so we'll put them as a comment here and future
    # generations will have to wrestle with the implications.
    #
    # In keripy as of Oct 31, 2025 they are only referenced in the codex
    #
    #{"0P", :GramHeadNeck,               "Gram Head Neck",                               	            12, 0},
    #{"0Q", :GramHead,                   "Gram Head",	                                                12, 0},
    #{"0R", :GramHeadAIDNeck,            "Gram Head AID Neck",	                                        12, 0},
    #{"0S", :GramHeadAID,                "Gram Head AID",	                                            12, 0}
end

defmodule Cesr.Primitive.Generator.FourCharacterTagPrimitives do
  @moduledoc "Generator for FourCharacterTagPrimitives"
  def typeDescriptions, do: [
    # {moduleCode, shortName, longDescription, textLength, pad_char_length}
    {"1AAF", :Tag4,  "Tag4 4 B64 encoded chars for special values", 8, 0},
    {"1AAN", :Tag4,  "Tag4 8 B64 encoded chars for special values", 12, 0}
    ]end

for {code, short_name, long_description, text_length, pad_char_length} <-
  Enum.concat([Cesr.Primitive.Generator.FourCharacterTagPrimitives.typeDescriptions,
               Cesr.Primitive.Generator.TwoCharacterTagPrimitives.typeDescriptions,
               Cesr.Primitive.Generator.OneCharacterTagPrimitives.typeDescriptions]) do

  module_name = Module.concat(Cesr.Primitive, "CD_#{code}_#{short_name}")
  {:ok, bits_of_code_rep} = Cesr.Utility.Base64Indicies.bits_of_b64_representation(code)
  bits_of_code_rep = Macro.escape(bits_of_code_rep)
  raw_size = (text_length - String.length(code) - pad_char_length) * 6
  payload_text_size = text_length - String.length(code) - pad_char_length

  defmodule module_name do
    @enforce_keys [:code, :payload]
    defstruct [:code, :payload]

    def new(primitive_bytes) when is_bitstring(primitive_bytes) and bit_size(primitive_bytes) == unquote(raw_size) do
      {:ok, struct(__MODULE__, %{code: unquote(code), payload: primitive_bytes})}
    end
    def new(_primitive_bytes) do
      {:error, "#{unquote(Atom.to_string(__MODULE__))} size must be #{unquote(raw_size)} bits long when constructing"}
    end

    def from_b64(<<unquote(code), pad_char::binary-size(unquote(pad_char_length)), potential_payload::binary-size(unquote(payload_text_size)), rest::binary>>) do
      {:ok, decoded_value} = Base.url_decode64(<<unquote(code), pad_char::bitstring, potential_payload::bitstring>>)
      <<unquote(bits_of_code_rep), _pad_char::size(unquote(pad_char_length)*6), payload::bitstring>> = decoded_value
      {{:ok, struct(__MODULE__, %{code: unquote(code), payload: payload})}, rest}
    end

    def from_binary(<<unquote(bits_of_code_rep), _pad_char::size(unquote(pad_char_length)*6), potential_payload::bitstring-size(unquote(payload_text_size)*6), rest::bitstring>>) do
      {{:ok, struct(__MODULE__, %{code: unquote(code), payload: <<potential_payload::bitstring>>})}, rest}
    end

    # 63::size(unquote(pad_char_length)) is because these tag primitives use "_" as their text padding representation instead of "A" == 0.
    # Maybe weird but we reproduce to match keripy
    def to_b64(%__MODULE__{} = tag_primitive) do
      Base.url_encode64(<<unquote(bits_of_code_rep), 63::size(unquote(pad_char_length)*6), tag_primitive.payload::bitstring>>)
    end

    # 63::size(unquote(pad_char_length)) is because these tag primitives use "_" as their text padding representation instead of "A" == 0.
    # Maybe weird but we reproduce to match keripy
    def to_binary(%__MODULE__{} = tag_primitive) do
      <<unquote(bits_of_code_rep), 63::size(unquote(pad_char_length)*6), tag_primitive.payload::bitstring>>
    end

    def properties do
      %{code: String.to_atom(unquote(code)), short_name: unquote(short_name),
        long_name: unquote(long_description), text_size: unquote(text_length)}
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
