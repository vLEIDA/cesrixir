defmodule Cesr.CodeTable.KeriCodeTableV1 do
  alias Cesr.CountCode.Generator.CntCodeV1Generator
  alias Cesr.Primitive.Generator.OneCharFixedPrimitive
  alias Cesr.Primitive.Generator.OneCharacterLabelPrimitives
  alias Cesr.Primitive.Generator.OneCharacterTagPrimitives
  alias Cesr.Primitive.Generator.TwoCharFixedPrimitive
  alias Cesr.Primitive.Generator.TwoCharacterTagPrimitives
  alias Cesr.Primitive.Generator.FourCharFixedPrimitive
  alias Cesr.Primitive.Generator.FourCharacterTagPrimitives
  alias Cesr.Primitive.Generator.VariableLengthPrimitive
  alias Cesr.Utility.Base64Indicies

  cnt_cd_type_descriptions = Enum.concat([CntCodeV1Generator.primitiveTypeDescriptions(),
                                          CntCodeV1Generator.quadletTypeDescriptions()])
  tag_label_type_descriptions = Enum.concat([FourCharacterTagPrimitives.typeDescriptions(),
                                             TwoCharacterTagPrimitives.typeDescriptions(),
                                             OneCharacterTagPrimitives.typeDescriptions(),
                                             OneCharacterLabelPrimitives.typeDescriptions()])
  primitive_type_descriptions = Enum.concat([OneCharFixedPrimitive.typeDescriptions(),
                                            TwoCharFixedPrimitive.typeDescriptions(),
                                            FourCharFixedPrimitive.typeDescriptions()])
  variable_length_type_descriptions = VariableLengthPrimitive.typeDescriptions()

  # Scratch space for codes
  cnt_cds = Enum.map(cnt_cd_type_descriptions, &("-" <> elem(&1, 0)))
  tag_cds = Enum.map(tag_label_type_descriptions, &(elem(&1, 0)))
  prim_cds = Enum.map(primitive_type_descriptions, &(elem(&1, 0)))
  var_cds = for x <- ["4", "5", "6", "7AA", "8AA", "9AA"], 
                y <- Enum.map(variable_length_type_descriptions, &(elem(&1, 0))), do: x <> y
  all_codes = Enum.concat([cnt_cds, tag_cds, prim_cds, var_cds])


  for {code, text_size, short_name, _long_name, _multiplier, _validation_func, _consumption_func} <- cnt_cd_type_descriptions do
    bits_of_code_rep = Macro.escape(Base64Indicies.bits_of_b64_representation!("-" <> code))
    count_code_module = Module.concat(Cesr.CountCodeKERIv1, "CD_#{String.replace(code, "-", "dash")}_#{short_name}")
    def get_B(m = <<unquote(bits_of_code_rep), _count::size(unquote(text_size)*6), _rest::bitstring>>) do
      unquote(count_code_module).from_binary(m)
    end
    def get_T(m = "-" <> unquote(code) <> <<_count::binary-size(unquote(text_size)), _rest::binary>>) do
      unquote(count_code_module).from_b64(m)
    end
  end

  for {code, short_name, _long_description, text_payload_length, _pad_char_length} <- tag_label_type_descriptions do
    bits_of_code_rep = Macro.escape(Base64Indicies.bits_of_b64_representation!(code))
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

  for primitive_generator_module <- [OneCharFixedPrimitive,
                                     TwoCharFixedPrimitive,
                                     FourCharFixedPrimitive] do
    for {code, short_name, _long_name, text_size} <- primitive_generator_module.typeDescriptions() do
      bits_of_code_rep = Macro.escape(Base64Indicies.bits_of_b64_representation!(code))
      primitive_module = Module.concat([Cesr.Primitive, "CD_#{code}_#{short_name}"])
      payload_size = primitive_generator_module.payload_size(text_size)

      def get_B(m = <<unquote(bits_of_code_rep), _payload::size(unquote(payload_size) * 6), _rest::bitstring>>) do
        unquote(primitive_module).from_binary(m)
      end
      def get_T(m = unquote(code) <> <<_payload::binary-size(unquote(payload_size)), _rest::binary>>) do
        unquote(primitive_module).from_b64(m)
      end
    end
  end

  for {variable_code, module_name} <- variable_length_type_descriptions do
    primitive_module = Module.concat(Cesr.Primitive, module_name)
    for val <- ["4", "5", "6", "7AA", "8AA", "9AA"] do
      code = val <> variable_code
      bits_of_code_rep = Macro.escape(Base64Indicies.bits_of_b64_representation!(code))
      count_cd_size = if String.starts_with?(code, ["4", "5", "6"]), do: 2, else: 4
      def get_B(m = <<unquote(bits_of_code_rep), _count::size(unquote(count_cd_size) * 6), _rest::bitstring>>) do
        unquote(primitive_module).from_binary(m)
      end
      def get_T(m = unquote(code) <> <<_count::binary-size(unquote(count_cd_size)), _rest::binary>>) do
        unquote(primitive_module).from_b64(m)
      end
    end
  end

  def get_B(_code) do
    # IO.inspect("Notfound binary code == #{code}")
    :notfound
  end
  def get_T(_code) do
    # IO.inspect("Notfound text code == #{code}")
    :notfound
  end

  def available_codes, do: unquote(all_codes)
end
