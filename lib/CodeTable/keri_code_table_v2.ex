defmodule Cesr.CodeTable.KeriCodeTableV2 do
  alias Cesr.Primitive.Generator.OneCharFixedPrimitive
  alias Cesr.Primitive.Generator.TwoCharFixedPrimitive
  alias Cesr.Primitive.Generator.FourCharFixedPrimitive
  alias Cesr.Primitive.Generator.VariableLengthPrimitive
  alias Cesr.Primitive.Generator.OneCharacterLabelPrimitives

  require Logger

  for {code, text_size, short_name, _long_name, _val_func, _cons_func} <- Cesr.CountCode.Generator.CntCodeV2Generator.typeDescriptions do
    bits_of_code_rep = Macro.escape(Cesr.Utility.Base64Indicies.bits_of_b64_representation!("-" <> code))
    count_code_module = Module.concat(Cesr.CountCodeKERIv2,
      "CD_#{String.replace(code, "-", "dash")}_#{short_name}")
    def get_B(m = <<unquote(bits_of_code_rep), _count::binary-size(unquote(text_size)*6), _rest::binary>>) do
      unquote(count_code_module).from_binary(m)
    end
    def get_T(m = "-" <> unquote(code) <> <<_count::binary-size(unquote(text_size)), _rest::binary>>) do
      # IO.inspect("Matched b64 count code")
      unquote(count_code_module).from_b64(m)
    end
  end

  for {code, short_name, _long_description, text_payload_length, _pad_char_length} <-
    Enum.concat([Cesr.Primitive.Generator.FourCharacterTagPrimitives.typeDescriptions,
                 Cesr.Primitive.Generator.TwoCharacterTagPrimitives.typeDescriptions,
                 Cesr.Primitive.Generator.OneCharacterTagPrimitives.typeDescriptions,
                 OneCharacterLabelPrimitives.typeDescriptions]) do
    bits_of_code_rep = Macro.escape(Cesr.Utility.Base64Indicies.bits_of_b64_representation!(code))
    tag_module_name = Module.concat(Cesr.Primitive, "CD_#{code}_#{short_name}")
    # text_payload_length is total length of string and since we're not matching padding here we'll just subtract the code length
    payload_text_size = text_payload_length - String.length(code)# - pad_char_length

    def get_B(m = <<unquote(bits_of_code_rep), _payload::size(unquote(payload_text_size)*6), _rest::bitstring>>) do
      unquote(tag_module_name).from_binary(m)
    end
    def get_T(m = unquote(code) <> <<_payload::binary-size(unquote(payload_text_size)), _rest::binary>>) do
      unquote(tag_module_name).from_b64(m)
    end
  end

  for primitive_generator_module <- [OneCharFixedPrimitive, TwoCharFixedPrimitive, FourCharFixedPrimitive] do
    for {code, short_name, _long_name, text_size} <- primitive_generator_module.typeDescriptions() do
      bits_of_code_rep = Macro.escape(Cesr.Utility.Base64Indicies.bits_of_b64_representation!(code))
      primitive_module = Module.concat([Cesr.Primitive, "CD_#{code}_#{short_name}"])
      payload_size = primitive_generator_module.payload_size(text_size)

      def get_B(m = <<unquote(bits_of_code_rep), _payload::size(unquote(payload_size)*6), _rest::bitstring>>) do
        # IO.inspect("Matched primitive_B #{unquote(code)} here")
        unquote(primitive_module).from_binary(m)
      end
      def get_T(m = unquote(code) <> <<_payload::binary-size(unquote(payload_size)), _rest::binary>>) do
        # IO.inspect("Matched primitive #{unquote(code)} here")
        unquote(primitive_module).from_b64(m)
      end
    end
  end

  for {variable_code, module_name} <- VariableLengthPrimitive.typeDescriptions do
    primitive_module = Module.concat(Cesr.Primitive, module_name)
    for val <- ["4", "5", "6", "7AA", "8AA", "9AA"] do
      code = val <> variable_code
      bits_of_code_rep = Macro.escape(Cesr.Utility.Base64Indicies.bits_of_b64_representation!(code))
      def get_B(m = <<unquote(bits_of_code_rep), _rest::bitstring>>) do
        unquote(primitive_module).from_binary(m)
      end
      def get_T(m = unquote(code) <> <<_rest::binary>>) do
        unquote(primitive_module).from_b64(m)
      end
    end
  end

  def get_B(_code) do
    # Logger.debug(~s"Code #{code} not found in #{__MODULE__}")
    # IO.inspect("Notfound binary code == #{code}", base: :hex)
    :notfound
  end
  def get_T(_code) do
    # Logger.debug(~s"Code #{code} not found in #{__MODULE__}")
    # IO.inspect("Notfound text code == #{code}", base: :hex)
    :notfound
  end
end
