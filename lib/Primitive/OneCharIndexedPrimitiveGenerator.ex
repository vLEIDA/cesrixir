defmodule Cesr.Index.OneCharIndexedPrimitiveGenerator do
  def typeDescriptions, do: [
    {"A", "Ed25519 indexed signature both same",      :Ed25519_Sig,         1, 88, true},
    {"B", "Ed25519 indexed signature current only",   :Ed25519_Crt_Sig,     1, 88, false}, # BC ondex size == 0
    {"C", "ECDSA secp256k1 indexed sig both same",    :ECDSA_256k1_Sig,     1, 88, true},
    {"D", "ECDSA secp256k1 indexed sig current only", :ECDSA_256k1_Crt_Sig, 1, 88, false}, # BC ondex size == 0
    {"E", "ECDSA secp256r1 indexed sig both same",    :ECDSA_256r1_Sig,     1, 88, true},
    {"F", "ECDSA secp256r1 indexed sig current only", :ECDSA_256r1_Crt_Sig, 1, 88, false} # BC ondex size == 0
  ]
end

for {code, long_name, short_name, ind_size, text_size, _index_eq_ondex?} <- Cesr.Index.OneCharIndexedPrimitiveGenerator.typeDescriptions do
  # This comes from table https://trustoverip.github.io/tswg-cesr-specification/#indexed-code-table
  # Make this line better if that table expands beyond current selectors
  padding_size = if String.slice(code, 0, 1) in ["0", "3"], do: 0, else: 4
  payload_size = Integer.floor_div((text_size - String.length(code) - ind_size) * 6 - padding_size, 8)

  {:ok, b2_rep_of_code} = Cesr.Utility.Base64Indicies.bits_of_b64_representation(code)
  escp_b2_rep_of_code = Macro.escape(b2_rep_of_code)
  preamble_length = String.length(code) + ind_size
  module_name = Module.concat(Cesr.Primitive.Indexes, "IDX_#{code}_#{short_name}")

  defmodule module_name do
    alias Cesr.Utility.Base64Indicies

    @enforce_keys [:code, :payload, :index]
    defstruct [:code, :payload, :index, :ondex]
    @type t :: %__MODULE__{code: binary(), payload: binary(), index: non_neg_integer(), ondex: non_neg_integer()}

    def new(primitive_bytes, index) when is_binary(primitive_bytes) and byte_size(primitive_bytes) == unquote(payload_size) and
                                         is_integer(index) and index in 0..64 do
      {:ok, struct(__MODULE__, %{code: unquote(code), payload: primitive_bytes, index: index, ondex: index})}
    end
    def new(_primitive_bytes, _index) do
      {:error, "#{unquote(Atom.to_string(__MODULE__))} payload must be #{unquote(payload_size)} bytes long and index must be a positive integers"}
    end

    def from_b64(unquote(code) <> <<idx::binary-size(unquote(ind_size)),
                                    potential_payload::binary-size(unquote(text_size - preamble_length)),
                                    rest::binary>>) do
      <<_cesr_code::size(6), _index_value::size(6), _padding::size(unquote(padding_size)), payload::bitstring>> =
        Base.url_decode64!(unquote(code) <> idx <> potential_payload)
      index = Base64Indicies.get_b64_index_for_char(idx)
      ret_struct = struct(__MODULE__, %{code: unquote(code), payload: payload, index: index, ondex: index})
      {{:ok, ret_struct}, rest}
    end
    def from_b64(_), do: {:error, "Doesn't match #{__MODULE__}"}

    def from_binary(<<unquote(escp_b2_rep_of_code),
                      idx::bits-size(unquote(ind_size * 6)),
                      0::size(unquote(padding_size)),
                      potential_payload::binary-size(unquote(payload_size)), rest::binary>>) do
      index = :binary.decode_unsigned(<<0::size(2), idx::bitstring>>)
      {{:ok, struct(__MODULE__, %{code: unquote(code), payload: potential_payload, index: index, ondex: index})}, rest}
    end

    def to_binary(%__MODULE__{} = index_primitive) do
      <<unquote(escp_b2_rep_of_code),
        index_primitive.index::size(6),
        0::size(unquote(padding_size)),
        index_primitive.payload::bitstring>>
    end

    def to_b64(%__MODULE__{} = index_primitive) do
      Base.url_encode64(<<unquote(escp_b2_rep_of_code),
        index_primitive.index::size(6),
        0::size(unquote(padding_size)),
        index_primitive.payload::bitstring>>)
    end

    def properties do
      %{code: String.to_atom(unquote(code)), short_name: unquote(short_name),
        long_name: unquote(long_name), text_size: unquote(text_size)}
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
