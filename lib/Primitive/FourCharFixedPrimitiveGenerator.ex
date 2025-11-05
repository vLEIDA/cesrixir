defmodule Cesr.Primitive.Generator.FourCharFixedPrimitive do
  def typeDescriptions, do: [
    {"1AAA", :ECDSA_256k1N,       "ECDSA secp256k1 verification key non-transferable, basic derivation.",             48},
    {"1AAB", :ECDSA_256k1,        "ECDSA public verification or encryption key, basic derivation",                    48},
    {"1AAC", :Ed448N,             "Ed448 non-transferable prefix public signing verification key. Basic derivation.", 80},
    {"1AAD", :Ed448,              "Ed448 public signing verification key. Basic derivation.",                         80},
    {"1AAE", :Ed448_Sig,          "Ed448 signature. Self-signing derivation.",                                        156},
    {"1AAG", :DateTime,           "Base64 custom encoded 32 char ISO-8601 DateTime",                                  36},
    {"1AAH", :X25519_Cipher_Salt, "X25519 sealed box 100 char qb64 Cipher of 24 char qb64 Salt",                      100},
    {"1AAI", :ECDSA_256r1N,       "ECDSA secp256r1 verification key non-transferable, basic derivation.",             48},
    {"1AAJ", :ECDSA_256r1,        "ECDSA secp256r1 verification or encryption key, basic derivation",                 48},
    {"1AAK", :Null,               "Null None or empty value",                                                         4},
    {"1AAL", :No,                 "No Falsey Boolean value",                                                          4},
    {"1AAM", :Yes,                "Yes Truthy Boolean value",                                                         4},
    # These last two are listed under variable raw size codes in the
    # spec as of 31-Oct-2025 but look more like the fixed size control
    # codes above so we add them here.  Maybe that's a mistake for the
    # future.
    {"1AAO", :EscCdMapValues,     "Escape code for escaping special map field values",                                4},
    {"1AAP", :EmptyValNonceStr,   "Empty value for nonce or string",                                                  4}
  ]
  # Note on 1AA0: This should be something higher than 12 probably but at the time we wrote this, this tag hadn't been implemented
  # in keripy and we'd already pushed a commit for the tag above which is now 12 characters long.  Not sure how its going to be
  # rectified in the scheme in the future.

  # cesr_primitive -> to_b64, to_binary, from_b64, from_binary, new(bytes)
  # keri_primitive[cesr_primitive] -> new(elixir_instance_of_primtive), print(), to_1AAG_b64, to_1AAG_to_binary
  # to_1AAG_b64, to_1AAG_to_binary, to_regular_b64, from_regular_b64

  def payload_size(text_size), do: Integer.floor_div((text_size - 4) * 6 - 0, 8)
end

for {code, short_name, long_name, text_size} <- Cesr.Primitive.Generator.FourCharFixedPrimitive.typeDescriptions do
  # payload_size = (text_size * 6 bits (b64) - 0 padding bits) / 8 bits (utf8)
  {:ok, ind_of_code} = Cesr.Utility.Base64Indicies.deserialize_value_in_b64_index_scheme(code)
  payload_size = Cesr.Primitive.Generator.FourCharFixedPrimitive.payload_size(text_size)
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

    def from_b64(unquote(code) <> <<potential_payload::binary-size(unquote(text_size) - 4), rest::binary>>) do
      <<_code_value::size(24), payload::bitstring>> = Base.url_decode64!(unquote(code) <> potential_payload)
      {{:ok, struct(__MODULE__, %{code: unquote(code), payload: payload})}, rest}
    end
    def from_b64(_), do: {:error, "Doesn't match #{__MODULE__}"}

    def from_binary(<<unquote(ind_of_code)::size(24), potential_payload::binary-size(unquote(payload_size)), rest::binary>>) do
      {{:ok, struct(__MODULE__, %{code: unquote(code), payload: potential_payload})}, rest}
    end

    def to_binary(%__MODULE__{} = four_char_primitive) do
      <<unquote(ind_of_code)::size(24), four_char_primitive.payload::bitstring>>
    end

    def to_b64(%__MODULE__{} = four_char_primitive) do
      Base.url_encode64(<<unquote(ind_of_code)::size(24), four_char_primitive.payload::bitstring>>)
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
