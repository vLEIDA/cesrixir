defmodule Cesr.Primitive.Generator.TwoCharFixedPrimitive do
  def typeDescriptions, do: [
    {"0A", :Random_salt_seed_nonce,      "Random salt, seed, nonce, private key, or sequence number of length 128 bits",  24},
    {"0B", :Ed25519_signature,           "Ed25519 signature",                                                             88},
    {"0C", :ECDSA_secp256k1_signature,   "ECDSA secp256k1 signature",                                                     88},
    {"0D", :Blake3_512_Digest,           "Blake3-512 Digest",                                                             88},
    {"0E", :Blake2b_512_Digest,          "Blake2b-512 Digest",                                                            88},
    {"0F", :SHA3_512_Digest,             "SHA3-512 Digest",                                                               88},
    {"0G", :SHA2_512_Digest,             "SHA2-512 Digest",                                                               88},
    {"0H", :Long_number_4_byte,          "Long number 4-byte b2",                                                          8},
    {"0I", :ECDSA_secp256r1_signature,   "ECDSA secp256r1 signature",                                                     88}
  ]
  def payload_size(text_size), do: Integer.floor_div((text_size - 2) * 6 - 4, 8)
end

for {code, short_name, long_name, text_size} <- Cesr.Primitive.Generator.TwoCharFixedPrimitive.typeDescriptions do
  # payload_size = (text_size * 6 bits (b64) - 4 padding bits) / 8 bits (utf8)
  {:ok, ind_of_code} = Cesr.Utility.Base64Indicies.deserialize_value_in_b64_index_scheme(code)
  payload_size = Cesr.Primitive.Generator.TwoCharFixedPrimitive.payload_size(text_size)
  module_name = Module.concat(Cesr.Primitive, "CD_#{code}_#{short_name}")

  defmodule module_name do
    @enforce_keys [:code, :payload]
    defstruct [:code, :payload]
    @type t :: %__MODULE__{code: binary(), payload: binary()}

    def new(primitive_bytes) when is_binary(primitive_bytes) and byte_size(primitive_bytes) == unquote(payload_size) do
      {:ok, struct(__MODULE__, %{code: unquote(code), payload: primitive_bytes})}
    end
    def new(_primitive_bytes) do
      {:error, "#{unquote(Atom.to_string(__MODULE__))} seed must be #{unquote(payload_size)} bytes long"}
    end

    def from_b64(unquote(code) <> <<potential_payload::binary-size(unquote(text_size) - 2), rest::binary>>) do
      <<_code_value::size(12), _padding::size(4), payload::bitstring>> = Base.url_decode64!(unquote(code) <> potential_payload)
      {{:ok, struct(__MODULE__, %{code: unquote(code), payload: payload})}, rest}
    end
    def from_b64(_), do: {:error, "Doesn't match #{__MODULE__}"}

    def from_binary(<<unquote(ind_of_code)::size(12), 0::size(4), potential_payload::binary-size(unquote(payload_size)), rest::binary>>) do
      {{:ok, struct(__MODULE__, %{code: unquote(code), payload: potential_payload})}, rest}
    end
    def from_binary(_), do: {:error, "Doesn't match, #{__MODULE__}"}

    def to_binary(%__MODULE__{} = two_char_primitive) do
      <<unquote(ind_of_code)::size(12), 0::size(4), two_char_primitive.payload::bitstring>>
    end

    def to_b64(%__MODULE__{} = two_char_primitive) do
      Base.url_encode64(<<unquote(ind_of_code)::size(12), 0::size(4), two_char_primitive.payload::bitstring>>)
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
