defmodule Cesr.Index.TwoCharIndexedPrimitiveGenerator do
  def typeDescriptions, do: [
    # {code, long name, short name, index size, ondex size, text_size, index_eq_ondex?}
    {"0A", "Ed448 indexed signature dual",             :Ed448_Sig,               1, 1, 156, false},
    {"0B", "Ed448 indexed signature current only",     :Ed448_Crt_Sig,           1, 1, 156, true},
    {"2A", "Ed25519 indexed sig big dual",             :Ed25519_Big_Sig,         2, 2,  92, false},
    {"2B", "Ed25519 indexed sig big current only",     :Ed25519_Big_Crt_Sig,     2, 2,  92, true},
    {"2C", "ECDSA secp256k1 indexed sig big dual",     :ECDSA_256k1_Big_Sig,     2, 2,  92, false},
    {"2D", "ECDSA secp256k1 idx sig big current only", :ECDSA_256k1_Big_Crt_Sig, 2, 2,  92, true},
    {"2E", "ECDSA secp256r1 idx sig big both same",    :ECDSA_256r1_Big_Sig,     2, 2,  92, false},
    {"2F", "ECDSA secp256r1 idx sig big current only", :ECDSA_256r1_Big_Crt_Sig, 2, 2,  92, true},
    {"3A", "Ed448 indexed signature big dual",         :Ed448_Big_Sig,           3, 3, 160, false},
    {"3B", "Ed448 indexed signature big current only", :Ed448_Big_Crt_Sig,       3, 3, 160, true}
  ]
end

for {code, long_name, short_name, ind_size, ond_size, text_size, index_eq_ondex?} <- Cesr.Index.TwoCharIndexedPrimitiveGenerator.typeDescriptions do
  # This comes from table https://trustoverip.github.io/tswg-cesr-specification/#indexed-code-table
  # Make this line better if that table expands beyond current selectors
  padding_size = if String.slice(code, 0, 1) in ["0", "3"], do: 0, else: 4
  payload_size = Integer.floor_div((text_size - String.length(code) - ind_size - ond_size) * 6 - padding_size, 8)

  {:ok, b2_rep_of_code} = Cesr.Utility.Base64Indicies.bits_of_b64_representation(code)
  escp_b2_rep_of_code = Macro.escape(b2_rep_of_code)
  preamble_length = String.length(code) + ind_size + ond_size
  module_name = Module.concat(Cesr.Primitive.Indexes, "IDX_#{code}_#{short_name}")

  odx_val = if index_eq_ondex? do 
    0
  else 
    quote do var!(index_primitive).ondex end 
  end # BC messed up keripy logic

  ondex = if index_eq_ondex? do 
    quote do var!(index) end 
  else 
    quote do calc_padding_to_byte_boundary(var!(odx)) end # BC messed up keripy logic
  end

  from_b64_odx = if index_eq_ondex? do 
    quote do var!(idx_val) end 
  else 
    quote do var!(odx_val) end # BC messed up keripy logic
  end

  new_ondex = if index_eq_ondex? do 
    quote do: var!(index)
  else 
    quote do: var!(ondex) # BC messed up keripy logic
  end

  defmodule module_name do
    alias Cesr.Utility.Base64Indicies
    @enforce_keys [:code, :payload, :index, :ondex]
    defstruct [:code, :payload, :index, :ondex]
    @type t :: %__MODULE__{code: binary(), payload: binary, index: non_neg_integer(), ondex: non_neg_integer()}

    # TODO calculate upper bound guards based on index/ondex size
    def new(primitive_bytes, index, ondex) when is_binary(primitive_bytes) and byte_size(primitive_bytes) == unquote(payload_size) and
                                                is_integer(index) and index >= 0 and
                                                is_integer(ondex) and ondex >= 0 do
      #ondex = if unquote(index_eq_ondex?), do: index, else: ondex # BC messed up keripy logic
      ondex = unquote(new_ondex)
      {:ok, struct(__MODULE__, %{code: unquote(code), payload: primitive_bytes, index: index, ondex: ondex})}
    end
    def new(_primitive_bytes, _index, _ondex) do
      {:error, "#{unquote(Atom.to_string(__MODULE__))} payload must be #{unquote(payload_size)} bytes long and index/ondex must be positive integers"}
    end

    def from_b64(unquote(code) <> <<idx::binary-size(unquote(ind_size)),
                                    odx::binary-size(unquote(ond_size)),
                                    potential_payload::binary-size(unquote(text_size - preamble_length)),
                                    rest::binary>>) do
      <<_preamble_data::size(unquote(preamble_length)*6),
        _padding::size(unquote(padding_size)), payload::bitstring>> = Base.url_decode64!(unquote(code) <> idx <> odx <> potential_payload)
      {:ok, idx_val} = Base64Indicies.deserialize_value_in_b64_index_scheme(idx)
      {:ok, odx_val} = Base64Indicies.deserialize_value_in_b64_index_scheme(odx)
      #odx_val = if unquote(index_eq_ondex?), do: idx_val, else: odx_val # BC messed up keripy logic
      _ = odx_val
      odx_val = unquote(from_b64_odx)
      {{:ok, struct(__MODULE__, %{code: unquote(code),
                                  payload: payload,
                                  index: idx_val,
                                  ondex: odx_val})}, rest}
    end
    def from_b64(_), do: {:error, "Doesn't match #{__MODULE__}"}

    defp calc_padding_to_byte_boundary(integer_value_bitstring) when is_bitstring(integer_value_bitstring) do
      sz = bit_size(integer_value_bitstring)
      padding = 8 - rem(sz, 8)
      :binary.decode_unsigned(<<0::size(padding), integer_value_bitstring::bitstring>>)
    end

    def from_binary(<<unquote(escp_b2_rep_of_code),
                    idx::bits-size(unquote(ind_size * 6)),
                    odx::bits-size(unquote(ond_size * 6)),
                    0::size(unquote(padding_size)),
                    potential_payload::binary-size(unquote(payload_size)), rest::binary>>) do
      index = calc_padding_to_byte_boundary(idx)
      #ondex = if unquote(index_eq_ondex?), do: index, else: calc_padding_to_byte_boundary(odx) # BC messed up keripy logic
      _ = odx
      ondex = unquote(ondex)
      {{:ok, struct(__MODULE__, %{code: unquote(code),
                                  payload: potential_payload,
                                  index: index,
                                  ondex: ondex})}, rest}
    end

    def to_binary(%__MODULE__{} = index_primitive) do
      #odx_val = if unquote(index_eq_ondex?), do: 0, else: index_primitive.ondex # BC messed up keripy logic
      odx_val = unquote(odx_val)
      <<unquote(escp_b2_rep_of_code),
        index_primitive.index::size(unquote(ind_size)*6),
        odx_val::size(unquote(ond_size)*6),
        0::size(unquote(padding_size)),
        index_primitive.payload::bitstring>>
    end

    def to_b64(%__MODULE__{} = index_primitive) do
      #odx_val = if unquote(index_eq_ondex?), do: 0, else: index_primitive.ondex # BC messed up keripy logic
      odx_val = unquote(odx_val)
      Base.url_encode64(<<unquote(escp_b2_rep_of_code),
                        index_primitive.index::size(unquote(ind_size)*6),
                        odx_val::size(unquote(ond_size)*6),
                        0::size(unquote(padding_size)),
                        index_primitive.payload::bitstring>>)
    end

    def properties do
      %{code: String.to_atom(unquote(code)), short_name: unquote(short_name), long_name: unquote(long_name), text_size: unquote(text_size)}
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
