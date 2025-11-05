defmodule Cesr.Utility.CesrPrettyPrint do
  @moduledoc """
  Pretty prints arbitrary CESR streams for readability by human.

  We serialize to JSON for display so CBOR, MGPK, and future CESR field maps
  won't be entirely correct.

  output:
    1. just structure of stream tabbed based on depth
    case stream_list = [H | T] do
       is_count_code(H)
           quads/triplets -> "\#\{StructName}(\#\{bytes} bytes/#\{quads} quads/#\{triplets} triplets) (which domain {B/T}) #\{QB64}"
           count -> "#\{StructName}(#\{count}) count (which domain {B/T}) #\{QB64}"
       is_primitive -> QB64 representation (which domain {B/T})
    end

    V_Label1(c=1) instead of -VBq

  A_ControllerIdxSigs(1 primitive, binary)
   QB64 Index 1
  A_ControllerIdxSigs(5 quadlets, b64) {QB64 Rep}
   QB64 Index 1
   QB64 Index 2
   QB64 Index 3
   ...
  A_ControllerIdxSigs(5 triplets, binary)

  list of cesr elements [a, b, c] -> pretty print each element
  cesr element -> print it, then print children at next indentation
  """

  alias Cesr.CodeTable.KeriElementGroupings
  alias Cesr.Utility.JsonUtils

  def main do
    cesr_stream_list = Cesr.consume_stream(IO.read(:stdio, :eof))
    IO.write(pretty_print(cesr_stream_list) <> "\n")
  end

#  @spec pretty_print(iodata(), iodata(), integer()) :: iodata()
  def pretty_print(list_or_cesr_element, acc \\ <<>>, depth \\ 0)
  def pretty_print([_h | _t] = list_or_cesr_element, acc, depth) do
    acc <> Enum.reduce(list_or_cesr_element, <<>>, 
                       fn h, inter_acc -> inter_acc <> pretty_print(h, <<>>, depth) end)
  end
  def pretty_print(%OrdMap{} = list_or_cesr_element, acc, depth) do
    {:ok, serialized_map} = JsonUtils.serialize(list_or_cesr_element)
    acc <> push_tabs(acc, depth) <> Jason.Formatter.pretty_print(serialized_map)
  end
  def pretty_print(list_or_cesr_element, acc, depth) 
    when is_struct(list_or_cesr_element) 
  do
    new_acc = acc <> push_tabs(acc, depth)
    %cesr_element_name{} = list_or_cesr_element
    short_name = strip_namespacing(cesr_element_name)
    # is count code
    cond do
      KeriElementGroupings.is_count_code?(cesr_element_name) ->
        if KeriElementGroupings.counts_children?(cesr_element_name) do
          new_acc <> "#{short_name}: (#{length(list_or_cesr_element.cesr_elements)}) count" <>
                     pretty_print(list_or_cesr_element.cesr_elements, <<>>, depth + 1)
        else
          new_acc <> "#{short_name}: (#{byte_size(Cesr.CesrElement.to_b64(list_or_cesr_element))}) bytes" <>
                     pretty_print(list_or_cesr_element.cesr_elements, <<>>, depth + 1)
        end
      KeriElementGroupings.is_primitive?(cesr_element_name) -> new_acc <>
        "#{short_name}: #{Cesr.CesrElement.to_b64(list_or_cesr_element)}"
      true -> IO.inspect(list_or_cesr_element)
    end
  end
  def pretty_print(potential_cesr_element, acc, depth) when is_tuple(potential_cesr_element) do
    dbg()
    case potential_cesr_element do
      {:ok, cesr_element} -> pretty_print(cesr_element, acc, depth)
      _ -> pretty_print(potential_cesr_element, acc, depth)
    end
  end
  def pretty_print(_, _, _) do
    :we_should_not_ever_get_here
  end

  defp push_tabs(acc, depth) when is_integer(depth) do
    acc <> "\n" <> String.duplicate("  ", depth)
  end

  defp strip_namespacing(module_fq_name) do
    [h|_t] = Enum.reverse(Module.split(module_fq_name))
    h
  end
end
