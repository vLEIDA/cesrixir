defmodule Cesr.Primitive.Generator.OneCharFixedPrimitive do
  def typeDescriptions, do: [
    # {moduleCode, shortName, longDescription, textPayloadLength}
    {"A", :Ed25519_Seed, "Ed25519 256 bit random seed for private key", 44},
    {"B", :Ed25519N, "Ed25519 verification key non-transferable, basic derivation.", 44},
    {"C", :X25519, "X25519 public encryption key, may be converted from Ed25519 or Ed25519N.", 44},
    {"D", :Ed25519, "Ed25519 verification key basic derivation", 44},
    {"E", :Blake3_256, "Blake3 256 bit digest self-addressing derivation.", 44},
    {"F", :Blake2b_256, "Blake2b 256 bit digest self-addressing derivation.", 44},
    {"G", :Blake2s_256, "Blake2s 256 bit digest self-addressing derivation.", 44},
    {"H", :SHA3_256, "SHA3 256 bit digest self-addressing derivation.", 44},
    {"I", :SHA2_256, "SHA2 256 bit digest self-addressing derivation.", 44},
    {"J", :ECDSA_256k1_Seed, "ECDSA secp256k1 256 bit random Seed for private key", 44},
    {"K", :Ed448_Seed, "Ed448 448 bit random Seed for private key", 76},
    {"L", :X448, "X448 public encryption key, converted from Ed448", 76},
    {"M", :Short, "Short 2 byte b2 number", 4},
    {"N", :Big, "Big 8 byte b2 number", 12},
    {"O", :X25519_Private, "X25519 private decryption key/seed, may be converted from Ed25519", 44},
    {"P", :X25519_Cipher_Seed, "X25519 sealed box 124 char qb64 Cipher of 44 char qb64 Seed", 124},
    {"Q", :ECDSA_256r1_Seed, "ECDSA secp256r1 256 bit random Seed for private key", 44},
    {"R", :Tall, "Tall 5 byte b2 number", 8},
    {"S", :Large, "Large 11 byte b2 number", 16},
    {"T", :Great, "Great 14 byte b2 number", 20},
    {"U", :Vast, "Vast 17 byte b2 number", 24},
    {"a", :Blind, "Blinding factor 256 bits, Cryptographic strength deterministically generated from random salt", 44}
  ]
  def payload_size(text_size), do: Integer.floor_div((text_size - 1) * 6 - 2, 8)
end

for {code, short_name, long_name, text_size} <- Cesr.Primitive.Generator.OneCharFixedPrimitive.typeDescriptions do
  # payload_size = (text_size * 6 bits (b64) - 2 padding bits) / 8 bits (utf8)
  ind_of_code = Cesr.Utility.Base64Indicies.get_b64_index_for_char(code)
  payload_size = Cesr.Primitive.Generator.OneCharFixedPrimitive.payload_size(text_size)
  module_name = Module.concat(Cesr.Primitive, "CD_#{code}_#{short_name}")

  defmodule module_name do
    @enforce_keys [:code, :payload]
    defstruct [:code, :payload]
    @type t :: %__MODULE__{code: binary(), payload: binary()}

    def new(primitive_bytes) when is_binary(primitive_bytes) and byte_size(primitive_bytes) == unquote(payload_size) do
      {:ok, struct(__MODULE__, %{code: unquote(code), payload: primitive_bytes})}
    end

    def new(_primitive_bytes) do
      {:error, "#{unquote(Atom.to_string(__MODULE__))} must be #{unquote(payload_size)} bytes long"}
    end

    def from_b64(unquote(code) <> <<potential_payload::binary-size(unquote(text_size) - 1), rest::binary>>) do
      <<_code_value::size(6), _padding::size(2), payload::bitstring>> = Base.url_decode64!(unquote(code) <> potential_payload)
      {{:ok, struct(__MODULE__, %{code: unquote(code), payload: payload})}, rest}
    end
    def from_b64(_), do: {:error, "Doesn't match #{__MODULE__}"}

    def from_binary(<<unquote(ind_of_code)::size(6), 0::size(2), potential_payload::binary-size(unquote(payload_size)), rest::binary>>) do
      {{:ok, struct(__MODULE__, %{code: unquote(code), payload: potential_payload})}, rest}
    end
    def from_binary(_), do: {:error, "Doesn't match #{__MODULE__}"}

    def to_binary(%__MODULE__{} = one_char_primitive) do
      <<unquote(ind_of_code)::size(6), 0::size(2), one_char_primitive.payload::bitstring>>
    end

    def to_b64(%__MODULE__{} = one_char_primitive) do
      Base.url_encode64(<<unquote(ind_of_code)::size(6), 0::size(2), one_char_primitive.payload::bitstring>>)
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
