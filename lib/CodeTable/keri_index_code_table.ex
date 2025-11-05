defmodule Cesr.CodeTable.KeriIndexCodeTable do
  alias Cesr.Index.OneCharIndexedPrimitiveGenerator
  alias Cesr.Index.TwoCharIndexedPrimitiveGenerator

  for {code, _long_name, short_name, ind_size, text_size, _index_eq_ondex?} <- OneCharIndexedPrimitiveGenerator.typeDescriptions do
    bits_of_code_rep = Macro.escape(Cesr.Utility.Base64Indicies.bits_of_b64_representation!(code))
    primitive_module = Module.concat([Cesr.Primitive.Indexes, "IDX_#{code}_#{short_name}"])
    payload_size = text_size - ind_size - String.length(code)

    def get_B(m = <<unquote(bits_of_code_rep), _payload::size(unquote(payload_size) * 6), _rest::bitstring>>) do
      unquote(primitive_module).from_binary(m)
    end
    def get_T(m = unquote(code) <> <<_payload::binary-size(unquote(payload_size)), _rest::binary>>) do
      unquote(primitive_module).from_b64(m)
    end
  end

  for {code, _long_name, short_name, ind_size, ond_size, text_size, _index_eq_ondex?} <- TwoCharIndexedPrimitiveGenerator.typeDescriptions do
    bits_of_code_rep = Macro.escape(Cesr.Utility.Base64Indicies.bits_of_b64_representation!(code))
    primitive_module = Module.concat([Cesr.Primitive.Indexes, "IDX_#{code}_#{short_name}"])
    payload_size = text_size - ind_size - ond_size - String.length(code)

    def get_B(m = <<unquote(bits_of_code_rep), _payload::size(unquote(payload_size) * 6), _rest::bitstring>>) do
      unquote(primitive_module).from_binary(m)
    end
    def get_T(m = unquote(code) <> <<_payload::binary-size(unquote(payload_size)), _rest::binary>>) do
      unquote(primitive_module).from_b64(m)
    end
  end

  def get_B(code) do
    IO.inspect("Notfound binary code == #{code}")
    :notfound
  end
  def get_T(code) do
    IO.inspect("Notfound text code == #{code}")
    :notfound
  end

  def all_indexes() do
    Enum.map(OneCharIndexedPrimitiveGenerator.typeDescriptions,
      fn x -> Module.concat([Cesr.Primitive.Indexes, "IDX_#{elem(x, 0)}_#{elem(x, 2)}"]) end)
    ++
    Enum.map(TwoCharIndexedPrimitiveGenerator.typeDescriptions,
      fn x -> Module.concat([Cesr.Primitive.Indexes, "IDX_#{elem(x, 0)}_#{elem(x, 2)}"]) end)
  end

  def is_index?(cesr_index_element) do
    %mod_name{} = cesr_index_element
    mod_name in all_indexes()
  end
end
