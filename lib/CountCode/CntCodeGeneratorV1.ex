defmodule Cesr.CountCode.Generator.CntCodeV1Generator do
  alias Cesr.CountCodeKERIv1.CountCodeValidationUtilities, as: ValFuncs
  alias Cesr.CountCodeKERIv1.CountCodeConsumptionUtilities, as: ConsumptionFuncs

  # {code, text_size, short_name, long_name, number_of_children, validation_function, consumption_function}
  #   number of children is derived from count code's semantics
  # ie. fnu+dts == 2 cesr primitives so the number of children of one element in that count code is 2.
  #     2 * count code length == total number of primitives in count code
  def primitiveTypeDescriptions, do: [
    {"A",  2, :ControllerIdxSigs,      "Qualified Base64 Indexed Signature.", 1, &ValFuncs.is_all_indexes?/1, &ConsumptionFuncs.b64_indexes/2},
    {"B",  2, :WitnessIdxSigs,         "Qualified Base64 Indexed Signature.", 1, &ValFuncs.is_all_indexes?/1, &ConsumptionFuncs.b64_indexes/2},
    # Code comment in keripy says pre+cig but updated spec and cesr-decoder streams have pre+sig so thats what we'll go with.
    {"C",  2, :NonTransReceiptCouples, "Composed Base64 Couple, pre+sig.", 2, &ValFuncs.is_pre_sig?/1, &ConsumptionFuncs.b64_pre_plus_sig/2},
    {"D",  2, :TransReceiptQuadruples, "Composed Base64 Quadruple, pre+snu+dig+sig.", 4, &ValFuncs.trivial/1, &ConsumptionFuncs.b64_pre_snu_dig_sig/2},
    {"E",  2, :FirstSeenReplayCouples, "Composed Base64 Couple, fnu+dts.", 2, &ValFuncs.trivial/1, &ConsumptionFuncs.b64_fnu_dts/2},
    {"F",  2, :TransIdxSigGroups,      "Composed Base64 Group, pre+snu+dig+ControllerIdxSigs group.", 4, &ValFuncs.trivial/1, &ConsumptionFuncs.b64_pre_snu_dig_ctrlidxsigs/2},
    {"G",  2, :SealSourceCouples,      "Composed Base64 couple, snu+dig of given delegator/issuer/transaction event, 2", 2, &ValFuncs.trivial/1, &ConsumptionFuncs.b64_snu_dig/2},
    {"H",  2, :TransLastIdxSigGroups,  "Composed Base64 Group, pre+ControllerIdxSigs group.", 2, &ValFuncs.trivial/1, &ConsumptionFuncs.b64_pre_ctrlidxsigs/2},
    {"I",  2, :SealSourceTriples,      "Composed Base64 triple, pre+snu+dig of anchoring source event", 3, &ValFuncs.trivial/1, &ConsumptionFuncs.b64_pre_snu_dig/2}
  ]
  # why -1 children? because we use quadlets instead of counting elements
  def quadletTypeDescriptions, do: [
    {"L",  2, :PathedMaterialCouples,       "Composed Grouped Pathed Material Quadlet (4 char each)", -1, &ValFuncs.trivial/1, &ConsumptionFuncs.trivial/2},
    {"-L", 2, :BigPathedMaterialCouples,    "Composed Grouped Pathed Material Quadlet (4 char each)", -1, &ValFuncs.trivial/1, &ConsumptionFuncs.trivial/2},
    {"T",  2, :GenericGroup,               "Generic Material Quadlet (Universal with override)", -1, &ValFuncs.trivial/1, &ConsumptionFuncs.universal/2 },
    {"-T", 2, :BigGenericGroup,            "Big Generic Material Quadlet (Universal with override)", -1, &ValFuncs.trivial/1, &ConsumptionFuncs.universal/2},
    {"U",  2, :BodyWithAttachmentGroup,    "Message Body plus Attachments Quadlet (Universal with Override).", -1, &ValFuncs.trivial/1, &ConsumptionFuncs.body_plus_attachment/2},
    {"-U", 2, :BigBodyWithAttachmentGroup, "Big Message Body plus Attachments Quadlet (Universal with Override)", -1, &ValFuncs.trivial/1, &ConsumptionFuncs.body_plus_attachment/2},
    {"V",  2, :AttachmentGroup,             "Composed Grouped Attached Material Quadlet (4 char each)", -1, &ValFuncs.trivial/1, &ConsumptionFuncs.trivial/2},
    {"-V", 5, :BigAttachmentGroup,          "Composed Grouped Attached Material Quadlet (4 char each)", -1, &ValFuncs.trivial/1, &ConsumptionFuncs.trivial/2},
    {"W",  2, :NonNativeBodyGroup,         "Message body Non-native enclosed with Texter", -1, &ValFuncs.trivial/1, &ConsumptionFuncs.trivial/2},
    {"-W", 2, :BigNonNativeBodyGroup,      "Big Message body Non-native enclosed with Texter", -1, &ValFuncs.trivial/1, &ConsumptionFuncs.trivial/2},
    {"Z",  2, :ESSRPayloadGroup,           "ESSR Payload Group (not implemented as quadlets)", -1, &ValFuncs.trivial/1, &ConsumptionFuncs.trivial/2},
    {"-Z", 2, :BigESSRPayloadGroup,        "Big ESSR Payload Group (not implemented as quadlets)", -1, &ValFuncs.trivial/1, &ConsumptionFuncs.trivial/2}
  ]
end

# --- top of memory stack ---
# consume_indexed_B
# consume_count_code_B
# consume_count_code_B
# --- bottom of stack ---

# Indexed Sig, 4 Signatures left
# Count_Code, 3 primitives left
# Count_Code, 2 primitives left

# Text or Binary or Raw (struct, runtime representation only)
# Any Primitives or Count Code or Indexed or Fixed Order (snu+dig or pre+cig)
# Count Code: given a fixed length or number of primitives, read that much

# consume_stream_B
# consume_stream_T
# consume_count_code_B
# consume_count_code_T
# consume_indexed_B
# consume_indexed_T

# consume_stream(bytes, current_byte, remaining_bytes, remaining_primitives,
#   domain=[T,B], primitive_types=[Indexed, Any, CountCodes])

# already implemented by consume_count_code_T or consume_count_code_B
# consume_stream(bytes, byte_count, primitive_count, primitive_queue)
# consume_stream(_, _, primitive_count=2, queue=[A_Ed, B_Sig, C_Sig])
# consume_stream(_, _, length=44)

# "C_NonTransReceiptCouples", length = 88 bytes
# read one from Prefixes, one from Cig, Pre, Cig, check no bytes left
# read stream for 88 bytes, then check that it's Prefix, Cig, Pre, Cig

# Cesr v1 framing code + count => [count of things]

for {code, text_size, short_name, long_name, number_of_children, validation_func, consumption_func} <-
  Cesr.CountCode.Generator.CntCodeV1Generator.primitiveTypeDescriptions
do
  bits_of_code =
    Macro.escape(Cesr.Utility.Base64Indicies.bits_of_b64_representation!("-" <> code)) # dashes in front of all count codes
  module_name = Module.concat(Cesr.CountCodeKERIv1, "CD_#{code}_#{short_name}")

  defmodule module_name do
    alias Cesr.Utility.Base64Indicies

    @enforce_keys [:cesr_elements]
    defstruct [:cesr_elements]
    @type t :: %__MODULE__{cesr_elements: list()}

    def new(cesr_elements) 
      when is_list(cesr_elements) and 
           rem(length(cesr_elements), unquote(number_of_children)) == 0
    do
      # We strip our {:ok, cesr_element} tuples in the happy path, in the
      # unhappy path the validation func will error
      #
      # Note(CAL): This seems kinda hacky... idk
      cesr_elements = Enum.map(cesr_elements,
        fn x -> case x do
                  {:ok, val} -> val # constructor case
                  {{:ok, val}, _rest} -> val # from_binary/from_b64 case where we're using it as constructor without other stuff on stream
                  _ -> x # raw struct case
                end
        end)
      if unquote(validation_func).(cesr_elements) do
        {:ok, %__MODULE__{cesr_elements: cesr_elements}}
      else
        {:error, "#{inspect(unquote(validation_func))} returned false!"}
      end
    end
    def new(cesr_elements) do
      {:error, "#{unquote(Atom.to_string(__MODULE__))} #{inspect(cesr_elements)}: must be a list and must have number of elements divisible by children of count code type"}
    end

    @spec from_b64(binary()) :: {{:ok, struct()}, binary()} | {:error, term()}
    def from_b64("-" <> unquote(code) <> <<count::binary-size(unquote(text_size)), rest::binary>>) do
      case Base64Indicies.deserialize_value_in_b64_index_scheme(count) do
        # split the stream for the current count code and the rest
        {:ok, 0} -> {{:ok, %__MODULE__{cesr_elements: []}}, rest}
        {:ok, numerical_value_of_count} -> case consume_count_code_T(rest, numerical_value_of_count, [], unquote(consumption_func)) do
                                            {:ok, cnt_cd_elements, rest_of_stream} -> {{:ok, %__MODULE__{cesr_elements: cnt_cd_elements}}, rest_of_stream}
                                            {:error, err_msg} -> {:error, err_msg}
                                          end
        {:error, err_msg} -> {:error, err_msg}
      end
    end
    def from_b64(_), do: {:error, "Doesn't match #{__MODULE__}"}

    @spec from_binary(binary()) :: {{:ok, struct()}, binary()} | {:error, term()}
    def from_binary(<<unquote(bits_of_code)::bitstring, count::bitstring-size(unquote(text_size)*6), rest::bitstring>>) do
      case calc_padding_to_byte_boundary(count) do
        # split the stream for the current count code and the rest
        0 -> {{:ok, struct(__MODULE__, %{cesr_elements: []})}, rest}
        numerical_value_of_count -> case consume_count_code_B(rest, numerical_value_of_count, [], unquote(consumption_func)) do
                                      {:ok, cnt_cd_elements, rest_of_stream} -> {{:ok, %__MODULE__{cesr_elements: cnt_cd_elements}}, rest_of_stream}
                                      {:error, err_msg} -> {:error, err_msg}
                                    end
        # no b64 deserialization so we can't throw an error here we
        # think??? {:error, err_msg} -> {:error, err_msg}
      end
    end

    def to_binary(%__MODULE__{} = this_count_code_struct) do
      encoded_payloads = Enum.map(this_count_code_struct.cesr_elements,
        fn x -> x.__struct__.to_binary(x) end)
      |> Enum.join
      # Floor div because we'll always be on a 3/4 byte boundary by construction
      number_of_elements = Integer.floor_div(length(this_count_code_struct.cesr_elements), unquote(number_of_children))
      <<unquote(bits_of_code), number_of_elements::size(unquote(text_size)*6), encoded_payloads::bitstring>>
    end

    def to_b64(%__MODULE__{} = this_count_code_struct) do
      encoded_payloads = Enum.map(this_count_code_struct.cesr_elements,
          fn x -> x.__struct__.to_b64(x) end)
        |> Enum.join
      # Floor div because we'll always be on a 3/4 byte boundary by construction
      number_of_child_groups = Integer.floor_div(length(this_count_code_struct.cesr_elements), unquote(number_of_children))
      {:ok, count_of_group} = Base64Indicies.serialize_value_in_b64_index_scheme(number_of_child_groups, unquote(text_size))
      "-" <> unquote(code) <> count_of_group <> encoded_payloads
    end

    def properties do
      %{code: String.to_atom(unquote(code)), short_name: unquote(short_name),
        long_name: unquote(long_name), text_size: unquote(text_size)}
    end

    defp consume_count_code_B(bytes, remaining_primitives, acc, consumption_func)
    defp consume_count_code_B(bytes, 0, acc, _consumption_func), do: {:ok, acc, bytes}
    defp consume_count_code_B(bytes, remaining_primitives, _acc, _consumption_func) when bytes == "" and 0 < remaining_primitives, do:
        {:error, "Remaining primitives but not enough bytes left on stream"}
    defp consume_count_code_B(bytes, remaining_primitives, acc, consumption_func) when byte_size(bytes) > 0 do
      case consumption_func.(bytes, :binary) do
        {{:ok, elements}, rest} -> consume_count_code_B(rest, remaining_primitives - 1, elements ++ acc, consumption_func)
        :notfound -> {:error, "count code not found"}
        {:error, err_msg} -> {:error, err_msg}
      end
    end

    defp consume_count_code_T(bytes, remaining_primitives, acc, consumption_func)
    defp consume_count_code_T(bytes, 0, acc, _consumption_func), do: {:ok, acc, bytes}
    defp consume_count_code_T(bytes, remaining_primitives, _acc, _consumption_func) 
      when bytes == "" and 0 < remaining_primitives
    do
      {:error, "Remaining primitives but not enough bytes left on stream"}
    end
    defp consume_count_code_T(bytes, remaining_primitives, acc, consumption_func) 
      when byte_size(bytes) > 0 
    do
      case consumption_func.(bytes, :b64) do
        {{:ok, elements}, rest} -> consume_count_code_T(rest, remaining_primitives - 1, elements ++ acc, consumption_func)
        :notfound -> {:error, "count code not found"}
        {:error, err_msg} -> {:error, err_msg}
      end
    end

    # Utility function to map a bitstring not aligned on a byte boundary to its integer representation
    defp calc_padding_to_byte_boundary(integer_value_bitstring) when is_bitstring(integer_value_bitstring) do
      sz = bit_size(integer_value_bitstring)
      padding = 8 - rem(sz, 8)
      :binary.decode_unsigned(<<0::size(padding), integer_value_bitstring::bitstring>>)
    end
  end

  # We implement our polymorphic protocol
  defimpl Cesr.CesrElement, for: module_name do
    def to_b64(cesr_element), do: unquote(module_name).to_b64(cesr_element)
    def to_binary(cesr_element), do: unquote(module_name).to_binary(cesr_element)
    def properties(_cesr_element), do: unquote(module_name).properties()
  end
end

for {code, text_size, short_name, long_name, _number_of_children, validation_func, consumption_func} <-
  Cesr.CountCode.Generator.CntCodeV1Generator.quadletTypeDescriptions
do
  bits_of_code =
    Macro.escape(Cesr.Utility.Base64Indicies.bits_of_b64_representation!("-"
    <> code)) # dashes in front of all count codes
  module_name = Module.concat(Cesr.CountCodeKERIv1,
    "CD_#{String.replace(code, "-", "dash")}_#{short_name}")

  defmodule module_name do
    alias Cesr.Utility.Base64Indicies

    @enforce_keys [:cesr_elements]
    defstruct [:cesr_elements]
    @type t :: %__MODULE__{cesr_elements: list()}

    def new(cesr_elements) when is_list(cesr_elements) do
      # We strip our {:ok, cesr_element} tuples in the happy path, in the unhappy path the validation func will error
      cesr_elements = Enum.map(cesr_elements,
        fn x -> case x do
                  {:ok, val} -> val # constructor case
                  {{:ok, val}, _rest} -> val # from_binary/from_b64 case where we're using it as constructor without other stuff on stream
                  _ -> x # raw struct case
                end
        end)
      if unquote(validation_func).(cesr_elements) do
        {:ok, struct(__MODULE__, %{cesr_elements: cesr_elements})}
      else
        {:error, "#{inspect(unquote(validation_func))} returned false!"}
      end
    end
    def new(cesr_elements) do
      {:error, "#{unquote(Atom.to_string(__MODULE__))} #{inspect(cesr_elements)}: must be a list"}
    end

    @spec from_b64(binary()) :: {{:ok, struct()}, binary()} | {:error, term()}
    def from_b64("-" <> unquote(code) <> <<count::binary-size(unquote(text_size)), rest::binary>>) do
      case Base64Indicies.deserialize_value_in_b64_index_scheme(count) do
        # split the stream for the current count code and the rest
        {:ok, 0} -> {{:ok, struct(__MODULE__, %{cesr_elements: []})}, rest}
        {:ok, numerical_value_of_count} ->
          <<count_code_bytes::binary-size(numerical_value_of_count * 4), rest_of_stream::binary>> = rest
          case consume_count_code_T(count_code_bytes, [], unquote(consumption_func)) do
            {:ok, cnt_cd_elements} -> {{:ok, %__MODULE__{cesr_elements: cnt_cd_elements}}, rest_of_stream}
            {:error, err_msg} -> {:error, err_msg}
          end
        {:error, err_msg} -> {:error, err_msg}
      end
    end
    def from_b64(_), do: {:error, "Doesn't match #{__MODULE__}"}

    @spec from_binary(binary()) :: {{:ok, struct()}, binary()} | {:error, term()}
    def from_binary(<<unquote(bits_of_code)::bitstring, count::bitstring-size(unquote(text_size)*6), rest::bitstring>>) do
      case calc_padding_to_byte_boundary(count) do
        # split the stream for the current count code and the rest
        0 -> {{:ok, struct(__MODULE__, %{cesr_elements: []})}, rest}
        numerical_value_of_count -> 
          <<count_code_bytes::binary-size(numerical_value_of_count * 3), rest_of_stream::binary>> = rest
          case consume_count_code_B(count_code_bytes, [], unquote(consumption_func)) do
            {:ok, cnt_cd_elements} -> {{:ok, %__MODULE__{cesr_elements: cnt_cd_elements}}, rest_of_stream}
            {:error, err_msg} -> {:error, err_msg}
          end
        # no b64 deserialization so we can't throw an error here we
        # think??? {:error, err_msg} -> {:error, err_msg}
      end
    end

    def to_binary(%__MODULE__{} = this_count_code_struct) do
      encoded_payloads = Enum.map(this_count_code_struct.cesr_elements,
        fn x -> x.__struct__.to_binary(x) end)
      |> Enum.join
      # Floor div because we'll always be on a 3/4 byte boundary by construction
      encoded_length_triplets = Integer.floor_div(byte_size(encoded_payloads), 3)
      <<unquote(bits_of_code), encoded_length_triplets::size(unquote(text_size)*6), encoded_payloads::bitstring>>
    end

    def to_b64(%__MODULE__{} = this_count_code_struct) do
      encoded_payloads = Enum.map(this_count_code_struct.cesr_elements,
          fn x -> x.__struct__.to_b64(x) end)
        |> Enum.join
      # Floor div because we'll always be on a 3/4 byte boundary by construction
      encoded_length_quadlets = Integer.floor_div(byte_size(encoded_payloads), 4)
      {:ok, serialized_count} = Base64Indicies.serialize_value_in_b64_index_scheme(encoded_length_quadlets, unquote(text_size))
      "-" <> unquote(code) <> serialized_count <> encoded_payloads
    end

    def properties do
      %{code: String.to_atom(unquote(code)), short_name: unquote(short_name),
        long_name: unquote(long_name), text_size: unquote(text_size)}
    end

    # termination
    defp consume_count_code_B(<<>>, acc, _consumption_func), do: {:ok, Enum.reverse(acc)}
    # transition
    defp consume_count_code_B(bytes, acc, consumption_func) do
      case consumption_func.(bytes, :binary) do
        {{:ok, elements}, rest} -> consume_count_code_B(rest, elements ++ acc, consumption_func)
        :notfound -> {:error, "count code not found"}
        {:error, err_msg} -> {:error, err_msg}
      end
    end

    # termination
    defp consume_count_code_T(<<>>, acc, _consumption_func), do: {:ok, Enum.reverse(acc)}
    # transition
    defp consume_count_code_T(bytes, acc, consumption_func) do
      case consumption_func.(bytes, :b64) do
        {{:ok, elements}, rest} -> consume_count_code_T(rest, elements ++ acc, consumption_func)
        :notfound -> {:error, "count code not found"}
        {:error, err_msg} -> {:error, err_msg}
      end
    end

    defp calc_padding_to_byte_boundary(integer_value_bitstring) when is_bitstring(integer_value_bitstring) do
      sz = bit_size(integer_value_bitstring)
      padding = 8 - rem(sz, 8)
      :binary.decode_unsigned(<<0::size(padding), integer_value_bitstring::bitstring>>)
    end
  end

  # We implement our polymorphic protocol
  defimpl Cesr.CesrElement, for: module_name do
    def to_b64(cesr_element), do: unquote(module_name).to_b64(cesr_element)
    def to_binary(cesr_element), do: unquote(module_name).to_binary(cesr_element)
    def properties(_cesr_element), do: unquote(module_name).properties()
  end
end

defmodule Cesr.CountCodeKERIv1.CountCodeValidationUtilities do
  @moduledoc """
    These will be the validation functions for count codes that utilize the keri element groupings.

    NOTE: due to ambiguity in how the specs are written, keripy has chosen to allow count codes containing
    no elements.  So for all functions, empty list should return true.
  """
  alias Cesr.CodeTable.KeriElementGroupings

  def trivial([]), do: true
  def trivial(list_of_cesr_elements) when is_list(list_of_cesr_elements) do
    true
  end

  def is_all_indexes?([]), do: true
  def is_all_indexes?(list_of_cesr_elements_in_cnt_cd) when is_list(list_of_cesr_elements_in_cnt_cd) do
    Enum.all?(list_of_cesr_elements_in_cnt_cd, &KeriElementGroupings.is_index?/1)
  end

  def is_pre_sig?([]), do: true
  def is_pre_sig?(list_of_cesr_elements_in_cnt_cd) when is_list(list_of_cesr_elements_in_cnt_cd) do
    Enum.chunk_every(list_of_cesr_elements_in_cnt_cd, 2) |>
      Enum.map(fn [maybe_prefix, maybe_sig] ->
                 KeriElementGroupings.is_prefix_derivation?(maybe_prefix) and
                 KeriElementGroupings.is_signature?(maybe_sig) end) |>
      Enum.all?()
  end

  def is_pre_snu_dig_sig?(_cesr_elements), do: :notimplemented
  def is_fnu_dts?(_cesr_elements), do: :notimplemented
  def is_pre_snu_sig_ctrlidxsigs?(_cesr_elements), do: :notimplemented
  def is_snu_dig?(_cesr_elements), do: :notimplemented
  def is_pre_ctrlidxsigs?(_cesr_elements), do: :notimplemented
  def is_pre_snu_dig?(_cesr_elements), do: :notimplemented
  def is_path_transidxsigs?(_cesr_elements), do: :notimplemented
  def is_root_saidpath?(_cesr_elements), do: :notimplemented
end

defmodule Cesr.CountCodeKERIv1.CountCodeConsumptionUtilities do
  @moduledoc """
    These will be the consumption functions for count codes that utilize the keri element groupings.

    Each function is a step-function that reads off the primitives suggested by
    the semantics and returns the typical recursive call tuple pattern we have
    elsewhere in the parser (except returning multiple elements instead of just one):
    ie. `{{:ok, elements}, rest_of_stream}`

    If any issue arises we return `{:error, err_msg}`

    NOTE: due to ambiguity in how the specs are written, keripy has chosen to allow count codes containing
    no elements.  So for all functions, empty list should return empty list
  """
  alias Cesr
  alias Cesr.CodeTable.KeriCodeTableV1
  alias Cesr.CodeTable.KeriCodeTableV2
  alias Cesr.CodeTable.KeriElementGroupings
  alias Cesr.CodeTable.KeriIndexCodeTable
  alias Cesr.CodeTable.UniversalProtocolGenusTable
  alias Cesr.CountCodeKERIv1
  alias Cesr.CountCodeKERIv2

  def trivial(cesr_stream, :binary) when is_binary(cesr_stream) do
    case KeriCodeTableV1.get_B(cesr_stream) do
      {{:ok, element}, rest} -> {{:ok, [element]}, rest}
      {:error, err_msg} -> {:error, err_msg}
    end
  end
  def trivial(cesr_stream, :b64) when is_binary(cesr_stream) do
    case KeriCodeTableV1.get_T(cesr_stream) do
      {{:ok, element}, rest} -> {{:ok, [element]}, rest}
      {:error, err_msg} -> {:error, err_msg}
    end
  end

  def b64_indexes(cesr_stream, :b64) when is_binary(cesr_stream) do
    # We pull from the index table so by definition the validation will always
    # be true if we succeed
    consume_and_test_elements(cesr_stream, &KeriIndexCodeTable.get_T/1, [fn _element -> true end])
  end
  def b64_indexes(_cesr_stream, :binary), do: {:error, "This count code can't support binary elements"}

  def b64_pre_plus_sig(cesr_stream, :b64) 
    when is_binary(cesr_stream) 
  do
    validations = [&KeriElementGroupings.is_prefix_derivation?/1,
                   &KeriElementGroupings.is_signature?/1]
    consume_and_test_elements(cesr_stream, &KeriCodeTableV1.get_T/1, validations)
    # "Element in prefix + indexed signature pair is not a prefix or indexed signature"
  end
  def b64_pre_plus_sig(cesr_stream, :binary) when is_binary(cesr_stream), do: {:error, "This count code can't support binary elements"}

  def b64_pre_snu_dig_sig(cesr_stream, :b64) when is_binary(cesr_stream) do 
    validations = [&KeriElementGroupings.is_prefix_derivation?/1,
      &KeriElementGroupings.is_sequence_number?/1,
      &KeriElementGroupings.is_digest?/1,
      &KeriElementGroupings.is_signature?/1]
    consume_and_test_elements(cesr_stream, &KeriCodeTableV1.get_T/1, validations)
  end
  def b64_pre_snu_dig_sig(cesr_stream, :binary) when is_binary(cesr_stream), do: {:error, "This count code can't support binary elements"}

  def b64_fnu_dts(cesr_stream, :b64) when is_binary(cesr_stream) do 
    validations = [&KeriElementGroupings.is_first_seen_number?/1,
      &KeriElementGroupings.is_date_primitive?/1]
    consume_and_test_elements(cesr_stream, &KeriCodeTableV1.get_T/1, validations)
    # {:error, "Element in first seen number + date pair is not a first seen number or date.  CESR Stream: #{inspect(cesr_stream)}"}
  end
  def b64_fnu_dts(cesr_stream, :binary) when is_binary(cesr_stream), do: {:error, "This count code can't support binary elements"}

  def b64_pre_snu_dig_ctrlidxsigs(cesr_stream, :b64) 
    when is_binary(cesr_stream) 
  do 
    validations = [&KeriElementGroupings.is_prefix_derivation?/1,
      &KeriElementGroupings.is_sequence_number?/1,
      &KeriElementGroupings.is_digest?/1,
      fn element -> match?(%CountCodeKERIv1.CD_A_ControllerIdxSigs{}, element) end]
    consume_and_test_elements(cesr_stream, &KeriCodeTableV1.get_T/1, validations)
  end
  def b64_pre_snu_dig_ctrlidxsigs(cesr_stream, :binary) when is_binary(cesr_stream), do: {:error, "This count code can't support binary elements"}

  def b64_snu_dig(cesr_stream, :b64) 
    when is_binary(cesr_stream) 
  do 
    validations = [&KeriElementGroupings.is_sequence_number?/1,
      &KeriElementGroupings.is_digest?/1]
    consume_and_test_elements(cesr_stream, &KeriCodeTableV1.get_T/1, validations)
  end
  def b64_snu_dig(cesr_stream, :binary) when is_binary(cesr_stream), do: {:error, "This count code can't support binary elements"}

  def b64_pre_ctrlidxsigs(cesr_stream, :b64) 
    when is_binary(cesr_stream) 
  do 
    validations = [&KeriElementGroupings.is_prefix_derivation?/1,
      fn element -> match?(%CountCodeKERIv1.CD_A_ControllerIdxSigs{}, element) end]
    consume_and_test_elements(cesr_stream, &KeriCodeTableV1.get_T/1, validations)
  end
  def b64_pre_ctrlidxsigs(cesr_stream, :binary) when is_binary(cesr_stream), do: {:error, "This count code can't support binary elements"}

  def b64_pre_snu_dig(cesr_stream, :b64) 
    when is_binary(cesr_stream)
  do 
    validations = [&KeriElementGroupings.is_prefix_derivation?/1,
      &KeriElementGroupings.is_sequence_number?/1,
      &KeriElementGroupings.is_digest?/1]
    consume_and_test_elements(cesr_stream, &KeriCodeTableV1.get_T/1, validations)
  end
  def b64_pre_snu_dig(cesr_stream, :binary) when is_binary(cesr_stream), do: {:error, "This count code can't support binary elements"}

  # If we were building a TLV protocol with all the properties he put in, we'd
  # just make an elegant recursive descent stack machine for count codes and
  # the spec and parser would be like 3 lines long and essentially consume_stream |>
  # foldl until we were done.  He however ascribes special meaning to flags at
  # certain points in the stack and thus we have do do these weird checks of
  # first? due to the requirement that only the first genus/protocol switch
  # actually change behavior due to the requirement that only the first
  # genus/protocol switch actually change behavior
  #
  # See: https://trustoverip.github.io/kswg-cesr-specification/#universal-code-table-genusversion-codes-that-allow-genusversion-override
  def universal(cesr_stream, cesr_domain, code_table_genus \\ :keri_aaacaa)
  def universal(cesr_stream, :b64, code_table_genus) do 
    # is there a protocol/genus switch in first element?
    case UniversalProtocolGenusTable.get_B(cesr_stream) do
      {{:ok, new_protocol_genus}, rest} -> _universal_T(rest, [new_protocol_genus], new_protocol_genus)
      :protocol_genus_not_found -> {:error, "Protocol or genus in #{inspect(cesr_stream)} not found"}
      :notprotocol_genus -> _universal_T(cesr_stream, [], code_table_genus)
    end
  end
  def universal(cesr_stream, :binary, code_table_genus) do
    # is there a protocol/genus switch in first element?
    case UniversalProtocolGenusTable.get_B(cesr_stream) do
      {{:ok, new_protocol_genus}, rest} -> _universal_B(rest, [new_protocol_genus], new_protocol_genus)
      :protocol_genus_not_found -> {:error, "Protocol or genus in #{inspect(cesr_stream)} not found"}
      :notprotocol_genus -> _universal_B(cesr_stream, [], code_table_genus)
    end
  end
  # Termination 
  # The regular path will reverse our list of elements
  defp _universal_B(<<>>, acc, _code_table_genus), do: {{:ok, acc}, ""}
  # Walker
  defp _universal_B(cesr_stream, acc, code_table_genus) do
    lookup = case code_table_genus do
      :keri_aaabaa -> KeriCodeTableV1.get_B(cesr_stream)
      :keri_aaacaa -> KeriCodeTableV2.get_B(cesr_stream)
      _ -> {:error, "This error in _universal_B should never occur"}
    end

    case lookup do
      :notfound -> {:error, "Code in #{inspect(cesr_stream)} not found"}
      {:error, _} = e -> e
      {{:ok, element}, rest} -> _universal_B(rest, [element | acc], code_table_genus)
    end
  end
  # Termination 
  # The regular path will reverse our list of elements
  defp _universal_T(<<>>, acc, _code_table_genus), do: {{:ok, acc}, ""}
  # Walker
  defp _universal_T(cesr_stream, acc, code_table_genus) do
    lookup = case code_table_genus do
      :keri_aaabaa -> KeriCodeTableV1.get_T(cesr_stream)
      :keri_aaacaa -> KeriCodeTableV2.get_T(cesr_stream)
      _ -> {:error, "This error in _universal_B should never occur"}
    end

    case lookup do
      :notfound -> {:error, "Code in #{inspect(cesr_stream)} not found"}
      {:error, _} = e -> e
      {{:ok, element}, rest} -> _universal_T(rest, [element | acc], code_table_genus)
    end
  end

  def body_plus_attachment(cesr_stream, :b64), do: _body_plus_attachment(cesr_stream)
  def body_plus_attachment(cesr_stream, :binary), do: _body_plus_attachment(cesr_stream)
  defp _body_plus_attachment(cesr_stream) do
    case Cesr.consume_stream(cesr_stream) do
      [%OrdMap{}, %CountCodeKERIv1.CD_V_AttachmentGroup{}] = e -> {{:ok, e}, ""}
      [%OrdMap{}, %CountCodeKERIv1.CD_dashV_BigAttachmentGroup{}] = e -> {{:ok, e}, ""}
      [%OrdMap{}, %CountCodeKERIv2.CD_C_AttachmentGroup{}] = e -> {{:ok, e}, ""}
      [%OrdMap{}, %CountCodeKERIv2.CD_dashC_BigAttachmentGroup{}] = e -> {{:ok, e}, ""}
      {:error, e} -> {:error, e}
      e -> {:error, "Consuming count code stream didn't yield body plus attachment.  Stream: #{inspect(e)}"}
    end
  end

  defp consume_and_test_elements(stream, table_lookup_function, validation_function_list, acc \\ [])
  defp consume_and_test_elements(stream, table_lookup_function, [validation_function | other_val_functions], acc) 
    when is_function(table_lookup_function) and is_function(validation_function)
  do
    case table_lookup_function.(stream) do
      {{:ok, element}, rest} -> 
        if validation_function.(element) do
          consume_and_test_elements(rest, table_lookup_function, other_val_functions, acc ++ [element])
        else
          {:error, "Element: #{inspect(element)} doesn't validate: #{inspect(validation_function)}"}
        end
      lookup_error -> lookup_error
    end
  end
  defp consume_and_test_elements(stream, _table_lookup_function, [], acc), do: {{:ok, acc}, stream}
end
