defmodule Cesr.Primitive.Generator.VariableLengthPrimitive do
  def typeDescriptions, do: [
    {"A", :CesrStringB64},
    {"B", :CesrBytes},
    {"C", :X25519SealedBoxCipherText},
    {"D", :X25519SealedBoxCipherB64},
    {"E", :X25519SealedBoxCipherBytes},
    {"F", :HPKEBaseCipherBytes},
    # As the astute among you may have noticed "Decimal" isn't a well known
    # serialization nor does the spec specify which particular serialization of
    # decimals we should use.  A look at the keripy source code reveals:
    #
    # "DecimalCodex is codex of all variable sized Base64 String representation
    #  of decimal numbers both signed and unsigned, float and int."
    #   
    # So I guess you can put floats and ints (signed/unsigned) in here
    # and hope for the best. 🤞
    #
    # A common L for the guy that cares so much about "precision of language"
    {"H", :DecimalNumber} 
  ]
end

for {variable_code, module_name} <- Cesr.Primitive.Generator.VariableLengthPrimitive.typeDescriptions do
  # We have codes for all the generated prefix-codes (4A, 5A, ... 9AAA, 5A, ...)
  codes = Enum.map(["4", "5", "6", "7AA", "8AA", "9AA"], fn cd -> cd <> variable_code end)

  bits_of_binary_code_preambles = Enum.map(["4", "5", "6", "7AA", "8AA", "9AA"],
      fn cd -> cd <> variable_code end)
    |> Enum.map(&Cesr.Utility.Base64Indicies.bits_of_b64_representation/1)
    |> Enum.map(fn {:ok, b64_repr} -> b64_repr end) # all inputs have valid representations by construction

  binary_code_preambles = Enum.map(["4", "5", "6", "7AA", "8AA", "9AA"],
    fn cd -> cd <> variable_code end)
  fq_module_name = Module.concat(Cesr.Primitive, module_name)

  defmodule fq_module_name do
    alias Cesr.Utility.Base64Indicies
    import Bitwise

    @moduledoc """
    This module implements the #{module_name} encoding/decodings representing
    variable length codes 4#{variable_code}, 5#{variable_code}, 6#{variable_code}, 7AA#{variable_code}, 8AA#{variable_code}, 9AA#{variable_code} in Keri genus AAACAA
    """

    @enforce_keys [:code, :payload]
    defstruct [:code, :payload]
    @type t :: %__MODULE__{code: binary(), payload: binary()}

    # Max size = (64^4)*3bytes possible values for code 7AAA with no padding
    @max_size 50_331_648
    # Max size small = (64^2)*3bytes possible values for code 4A with no padding
    @max_size_small 12_288

    @doc """
    Due to the way KERIpy puts smaller values in bigger codes (asking the question, why have multiple codes at all???)
    we need a way to force the code.  "code" can take any of the variable length code values and force an element of that
     code type to be instantiated instead of the automagical constructor of the struct.
    """
    def new(raw_bytes, code \\ :auto)
    def new(raw_bytes, code) when byte_size(raw_bytes) < @max_size do
      code_validated = case code do
        code when code in unquote(codes) -> code
        :auto -> :auto
        _ -> {:error, "Code not valid for #{unquote(module_name)}"}
      end
      {:ok, struct(unquote(fq_module_name), %{code: code_validated, payload: raw_bytes})}
    end
    def new(_, code), do: {:error, "payload too large for #{unquote(module_name)} Code #{code}"}

    # 0..5 we map over numbers rather than the typedescriptions in the generator module above.
    for i <- 0..5 do
      padding = Integer.mod(i, 3) # How far off a 3byte boundary our payload is
      bytes_of_preamble = Macro.escape(Enum.at(binary_code_preambles, i))
      bits_of_preamble = Macro.escape(Enum.at(bits_of_binary_code_preambles, i))
      count_size = if i < 3, do: 2, else: 4
      count_bit_size = count_size * 6

      def from_binary(<<unquote(bits_of_preamble), count::size(unquote(count_bit_size)), rest::bitstring>>) do
        byte_size = byte_size_B_cnt?(count) # read payload size from the 2 or 4 base64 chars
        <<payload::binary-size(byte_size), rest_of_rest::binary>> = rest # split into payload & rest
        <<_padding_bytes::binary-size(unquote(padding)), payload_shifted::binary>> = payload # remove padding
        {unquote(fq_module_name).new(payload_shifted, unquote(bytes_of_preamble)), rest_of_rest}
      end
      # def from_binary(cesr_code), do: {:error, "#{unquote(module_name)} (B domain) doesn't match code structure: #{cesr_code}"}

      def from_b64(<<unquote(bytes_of_preamble), count::binary-size(unquote(count_size)), rest::binary>>) do
        byte_size = byte_size_T_cnt?(count)
        <<payload::binary-size(byte_size), rest_of_rest::binary>> = rest
        decoded_payload = Base.url_decode64!(payload)
        <<_padding::binary-size(unquote(padding)), payload_shifted::bitstring>> = decoded_payload
        {unquote(fq_module_name).new(payload_shifted, unquote(bytes_of_preamble)), rest_of_rest}
      end
      #def from_b64(cesr_code), do: {:error, "#{unquote(module_name)} (T domain) doesn't match code structure: #{cesr_code}"}
    end

    def to_binary(variable_length_payload = %__MODULE__{}), do: to_binary(variable_length_payload.payload, variable_length_payload.code)
    # If we force a big code we'll put a small payload on one of the bigger codes even when we don't have to.
    def to_binary(payload, input_code) do
      mod_size = Integer.mod(byte_size(payload), 3)
      validated_switching_code = get_validated_switching_code(payload, input_code)

      case {mod_size, validated_switching_code} do
        {0, true} ->
          <<Cesr.Utility.Base64Indicies.bits_of_b64_representation!(unquote(Macro.escape(Enum.at(binary_code_preambles, 0))))::bitstring,   count_triplets(payload, 2)::bitstring, payload::bitstring>>
        {0, false} ->
          <<Cesr.Utility.Base64Indicies.bits_of_b64_representation!(unquote(Macro.escape(Enum.at(binary_code_preambles, 3))))::bitstring, count_triplets(payload, 4)::bitstring, payload::bitstring>>
        # Pad with one byte to get to 3-byte boundary
        {2, true} -> padded_payload = << 0::size(8), payload::bitstring >>
          <<Cesr.Utility.Base64Indicies.bits_of_b64_representation!(unquote(Macro.escape(Enum.at(binary_code_preambles, 1))))::bitstring,   count_triplets(padded_payload, 2)::bitstring, padded_payload::bitstring>>
        {2, false} -> padded_payload = << 0::size(8), payload::bitstring >>
          <<Cesr.Utility.Base64Indicies.bits_of_b64_representation!(unquote(Macro.escape(Enum.at(binary_code_preambles, 4))))::bitstring, count_triplets(padded_payload, 4)::bitstring, padded_payload::bitstring>>
        # Pad two bytes to get to 3-byte boundary
        {1, true} -> padded_payload = << 0::size(16), payload::bitstring >>
          <<Cesr.Utility.Base64Indicies.bits_of_b64_representation!(unquote(Macro.escape(Enum.at(binary_code_preambles, 2))))::bitstring,   count_triplets(padded_payload, 2)::bitstring, padded_payload::bitstring>>
        {1, false} -> padded_payload = << 0::size(16), payload::bitstring >>
          <<Cesr.Utility.Base64Indicies.bits_of_b64_representation!(unquote(Macro.escape(Enum.at(binary_code_preambles, 5))))::bitstring, count_triplets(padded_payload, 4)::bitstring, padded_payload::bitstring>>
        {_, {:error, err_msg}} -> {:error, err_msg}
      end
    end

    def to_b64(variable_length_payload = %__MODULE__{}), do: to_b64(variable_length_payload.payload, variable_length_payload.code)
    # Code can be in :auto or valid code
    # If we force a big code we'll put a small payload on one of the bigger codes even when we don't have to.
    def to_b64(variable_length_payload, input_code) do
      mod_size = Integer.mod(byte_size(variable_length_payload), 3)
      is_small? = get_validated_switching_code(variable_length_payload, input_code)

      case {mod_size, is_small?} do
        {0, true} -> payload = Base.url_encode64(variable_length_payload)
          unquote(Macro.escape(Enum.at(binary_code_preambles, 0))) <> count_quadlets(payload, 2) <> payload
        {0, false} -> payload = Base.url_encode64(variable_length_payload)
        unquote(Macro.escape(Enum.at(binary_code_preambles, 3))) <> count_quadlets(payload, 4) <> payload
        # padded with 1 byte to get to 3-byte boundary
        {2, true} -> payload = << 0::size(8), variable_length_payload::bitstring >>
          b64_encoded_payload = Base.url_encode64(payload)
          unquote(Macro.escape(Enum.at(binary_code_preambles, 1))) <> count_quadlets(b64_encoded_payload, 2) <> b64_encoded_payload
        {2, false} -> payload = << 0::size(8), variable_length_payload::bitstring >>
          b64_encoded_payload = Base.url_encode64(payload)
          unquote(Macro.escape(Enum.at(binary_code_preambles, 4))) <> count_quadlets(b64_encoded_payload, 4) <> b64_encoded_payload
        # padded with 2 bytes to get to 3-byte boundary
        {1, true} -> payload = << 0::size(16), variable_length_payload::bitstring >>
        b64_encoded_payload = Base.url_encode64(payload)
        unquote(Macro.escape(Enum.at(binary_code_preambles, 2))) <> count_quadlets(b64_encoded_payload, 2) <> b64_encoded_payload
        {1, false} -> payload = << 0::size(16), variable_length_payload::bitstring >>
          b64_encoded_payload = Base.url_encode64(payload)
          unquote(Macro.escape(Enum.at(binary_code_preambles, 5))) <> count_quadlets(b64_encoded_payload, 4) <> b64_encoded_payload
        {_, {:error, err_msg}} -> {:error, err_msg}
      end
    end

    def properties do
      %{code: String.to_atom(unquote(variable_code)), short_name: :notimplemented, long_name: "Not implemented", text_size: 1}
    end

    @spec get_validated_switching_code(binary(), binary() | :auto) :: true | false | {atom(), binary()}
    defp get_validated_switching_code(variable_length_payload, code) do
      size = byte_size(variable_length_payload)
      fits_in_small? = (size <= @max_size_small - 1)
      fits_in_big? = (size <= @max_size - 1)
      is_small_code? = code != :auto and String.length(code) == 2
      is_big_code? = code != :auto and String.length(code) == 4

      # v: small c: small => small
      # v: small c: big   => big
      # v: big   c: big   => big
      case code do
        :auto when fits_in_small?                          -> true
        :auto when not fits_in_small? and fits_in_big?     -> false
        :auto when not fits_in_small? and not fits_in_big? -> {:error, "Payload doesn't fit in a variable length cesr field"}
        _ when (fits_in_small? and is_small_code?)         -> true
        _ when (not fits_in_small? and is_small_code?)     -> {:error, "Payload doesn't fit in code #{code}"}
        _ when (fits_in_big? and is_big_code?)             -> false
        _ when (not fits_in_big? and is_big_code?)         -> {:error, "Payload doesn't fit in code #{code}"}
      end
    end

    defp byte_size_T_cnt?(count_quadlets_in_b64) when count_quadlets_in_b64 >= 0 do
      case Base64Indicies.deserialize_value_in_b64_index_scheme(count_quadlets_in_b64) do
        {:ok, count} -> count * 4
        {:error, errors} -> {:error, errors}
      end
    end

    defp byte_size_B_cnt?(count_tritets_in_binary_domain) when count_tritets_in_binary_domain >= 0 do
      count_tritets_in_binary_domain * 3
    end

    defp count_quadlets(payload, count_size_in_T_domain) do
      {:ok, val} = Base64Indicies.serialize_value_in_b64_index_scheme(
        Integer.floor_div(byte_size(payload), 4), count_size_in_T_domain)
      val
    end

    defp count_triplets(payload, count_size_in_T_domain) do
      val = Integer.floor_div(byte_size(payload), 3)
      case count_size_in_T_domain do
        # Couldn't quite figure out how to do this with binary slicing itself but this works
        2 -> <<(val &&& 0b111111_111111)::size(12)>> # size of 2 in text domain == 12 bits in binary domain
        4 -> <<(val &&& 0b111111_111111_111111_111111)::size(24)>> # size of 4 in text domain == 24 bits in binary domain
      end
    end
  end

  # We implement our polymorphic protocol
  defimpl Cesr.CesrElement, for: fq_module_name do
    def to_b64(cesr_element), do: unquote(fq_module_name).to_b64(cesr_element)
    def to_binary(cesr_element), do: unquote(fq_module_name).to_binary(cesr_element)
    def properties(_cesr_element), do: unquote(fq_module_name).properties()
  end

  defimpl Jason.Encoder, for: fq_module_name do
    def encode(value, opts), do: Jason.Encode.string(unquote(fq_module_name).to_b64(value), opts)
  end
end
