defmodule Cesr.CountCode.Generator.CntCodeV2Generator do
  alias Cesr.CountCodeKERIv2.CountCodeValidationUtilities, as: ValFuncs
  alias Cesr.CountCodeKERIv2.CountCodeConsumptionUtilities, as: ConsumptionFuncs

  def typeDescriptions, do: [
    {"A",  2, :GenericGroup, "Generic Group (Universal with Override).", &ValFuncs.trivial?/1, &ConsumptionFuncs.universal/2},
    {"-A", 5, :BigGenericGroup, "Big Generic Group (Universal with Override).", &ValFuncs.trivial?/1, &ConsumptionFuncs.universal/2},
    {"B",  2, :BodyWithAttachmentGroup, "Message Body plus Attachments Group (Universal with Override).", &ValFuncs.trivial?/1, &ConsumptionFuncs.universal/2},
    {"-B", 5, :BigBodyWithAttachmentGroup, "Big Message Body plus Attachments Group (Universal with Override).", &ValFuncs.trivial?/1, &ConsumptionFuncs.universal/2},
    {"C",  2, :AttachmentGroup, "Message Attachments Only Group (Universal with Override).", &ValFuncs.trivial?/1, &ConsumptionFuncs.universal/2},
    {"-C", 5, :BigAttachmentGroup, "Big Attachments Only Group (Universal with Override).", &ValFuncs.trivial?/1, &ConsumptionFuncs.universal/2},
    {"D",  2, :DatagramSegmentGroup, "Datagram Segment Group (Universal).", &ValFuncs.trivial?/1, &ConsumptionFuncs.universal/2},
    {"-D", 5, :BigDatagramSegmentGroup, "Big Datagram Segment Group (Universal).", &ValFuncs.trivial?/1, &ConsumptionFuncs.universal/2},
    {"E",  2, :ESSRWrapperGroup, "ESSR Wrapper Group (Universal).", &ValFuncs.trivial?/1, &ConsumptionFuncs.universal/2},
    {"-E", 5, :BigESSRWrapperGroup, "Big ESSR Wrapper Group (Universal).", &ValFuncs.trivial?/1, &ConsumptionFuncs.universal/2},
    {"F",  2, :FixBodyGroup, "Fixed Field Message Body Group (Universal).", &ValFuncs.trivial?/1, &ConsumptionFuncs.universal/2},
    {"-F", 5, :BigFixBodyGroup, "Big Fixed Field Message Body Group (Universal).", &ValFuncs.trivial?/1, &ConsumptionFuncs.universal/2},
    {"G",  2, :MapBodyGroup, "Field Map Message Body Group (Universal).", &ValFuncs.trivial?/1, &ConsumptionFuncs.universal/2},
    {"-G", 5, :BigMapBodyGroup, "Big Field Map Message Body Group (Universal).", &ValFuncs.trivial?/1, &ConsumptionFuncs.universal/2},
    {"H",  2, :NonNativeBodyGroup, "Message body Non-native enclosed with Texter", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"-H", 5, :BigNonNativeBodyGroup, "Big Message body Non-native enclosed with Texter", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"I",  2, :GenericMapGroup, "Generic Field Map Group (Universal).", &ValFuncs.trivial?/1, &ConsumptionFuncs.universal/2},
    {"-I", 5, :BigGenericMapGroup, "Big Generic Field Map Group (Universal).", &ValFuncs.trivial?/1, &ConsumptionFuncs.universal/2},
    {"J",  2, :GenericListGroup, "Generic List Group (Universal).", &ValFuncs.trivial?/1, &ConsumptionFuncs.universal/2},
    {"-J", 5, :BigGenericListGroup, "Big Generic List Group (Universal).", &ValFuncs.trivial?/1, &ConsumptionFuncs.universal/2},
    {"K",  2, :ControllerIdxSigs, "Controller Indexed Signature(s) of qb64.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"-K", 5, :BigControllerIdxSigs, "Big Controller Indexed Signature(s) of qb64.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"L",  2, :WitnessIdxSigs, "Witness Indexed Signature(s) of qb64.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"-L", 5, :BigWitnessIdxSigs, "Big Witness Indexed Signature(s) of qb64.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"M",  2, :NonTransReceiptCouples, "NonTrans Receipt Couple(s), pre+cig.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"-M", 5, :BigNonTransReceiptCouples, "Big NonTrans Receipt Couple(s), pre+cig.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"N",  2, :TransReceiptQuadruples, "Trans Receipt Quadruple(s), pre+snu+dig+sig.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"-N", 5, :BigTransReceiptQuadruples, "Big Trans Receipt Quadruple(s), pre+snu+dig+sig.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"O",  2, :FirstSeenReplayCouples, "First Seen Replay Couple(s), fnu+dts.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"-O", 5, :BigFirstSeenReplayCouples, "First Seen Replay Couple(s), fnu+dts.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"P",  2, :PathedMaterialCouples, "Pathed Material couples. path+text", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"-P", 5, :BigPathedMaterialCouples, "Big Pathed Material couples. path+text", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"Q",  2, :DigestSealSingles, "Digest Seal Single(s), dig of sealed data.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"-Q", 5, :BigDigestSealSingles, "Big Digest Seal Single(s), dig of sealed data.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"R",  2, :MerkleRootSealSingles, "Merkle Tree Root Digest Seal Single(s), dig of sealed data.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"-R", 5, :BigMerkleRootSealSingles, "Merkle Tree Root Digest Seal Single(s), dig of sealed data.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"S",  2, :SealSourceCouples, "Seal Source Couple(s), snu+dig of source sealing or sealed event.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"-S", 5, :BigSealSourceCouples, "Seal Source Couple(s), snu+dig of source sealing or sealed event.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"T",  2, :SealSourceTriples, "Seal Source Triple(s), pre+snu+dig of source sealing or sealed event.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"-T", 5, :BigSealSourceTriples, "Seal Source Triple(s), pre+snu+dig of source sealing or sealed event.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"U",  2, :SealSourceLastSingles, "Seal Source Couple(s), pre of last source sealing or sealed event.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"-U", 5, :BigSealSourceLastSingles, "Big Seal Source Couple(s), pre of last source sealing or sealed event.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"V",  2, :BackerRegistrarSealCouples, "Backer Registrar Seal Couple(s), brid+dig of sealed data.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"-V", 5, :BigBackerRegistrarSealCouples, "Big Backer Registrar Seal Couple(s), brid+dig of sealed data.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"W",  2, :TypedDigestSealCouples, "Typed Digest Seal Couple(s), type seal vers+dig of sealed data.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"-W", 5, :BigTypedDigestSealCouples, "Big Typed Digest Seal Couple(s), type seal vers+dig of sealed data.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"X",  2, :TransIdxSigGroups, "Trans Indexed Signature Group(s), pre+snu+dig+CtrControllerIdxSigs of qb64.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"-X", 5, :BigTransIdxSigGroups, "Big Trans Indexed Signature Group(s), pre+snu+dig+CtrControllerIdxSigs of qb64.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"Y",  2, :TransLastIdxSigGroups, "Trans Last Est Evt Indexed Signature Group(s), pre+CtrControllerIdxSigs of qb64.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"-Y", 5, :BigTransLastIdxSigGroups, "Big Trans Last Est Evt Indexed Signature Group(s), pre+CtrControllerIdxSigs of qb64.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"Z",  2, :ESSRPayloadGroup, "ESSR Payload Group.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"-Z", 5, :BigESSRPayloadGroup, "Big ESSR Payload Group.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"a",  2, :BlindedStateQuadruples, "Blinded transaction event state quadruples blid+uuid+said+state.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"-a", 5, :BigBlindedStateQuadruples, "Big Blinded transaction event state quadruples blid+uuid+said+state.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"b",  2, :BoundStateSextuples, "Bound Blinded transaction event state sextuples blid+uuid+said+state+bsnu+bsaid.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"-b", 5, :BigBoundStateSextuples, "Big Bound Blinded transaction event state sextuples blid+uuid+said+state+bsnu+bsaid.", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"c",  2, :TypedMediaQuadruples, "Typed and Blinded IANA media type quadruples blid+uuid+type+media", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2},
    {"-c", 5, :BigTypedMediaQuadruples, "Big Type and Blinded IANA media type  quadruples blid+uuid+type+media", &ValFuncs.trivial?/1, &ConsumptionFuncs.trivial/2}]
end

for {code, text_size, short_name, long_name, validation_func,
  consumption_func} <-
    Cesr.CountCode.Generator.CntCodeV2Generator.typeDescriptions
  do
  bits_of_code = Macro.escape(Cesr.Utility.Base64Indicies.bits_of_b64_representation!("-" <> code)) # dashes in front of all count codes
  
  # We replace "-" with dash because we can't use dash in module names
  # If we ever get tables with underscores we'll have to do the same
  module_name = Module.concat(Cesr.CountCodeKERIv2,
    "CD_#{String.replace(code, "-", "dash")}_#{short_name}")

  defmodule module_name do
    alias Cesr.Utility.Base64Indicies
    alias Cesr.CodeTable.KeriCodeTableV2

    @enforce_keys [:cesr_elements]
    defstruct [:cesr_elements]

    def new(cesr_elements) when is_list(cesr_elements) do
      # We strip our {:ok, cesr_element} tuples in the happy path, in
      # the unhappy path the validation func will error
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
        {:ok, struct(__MODULE__, %{cesr_elements: cesr_elements})}
      else
        {:error, "#{inspect(unquote(validation_func))} returned false!"}
      end
    end
    def new(cesr_elements) do
      {:error, "#{unquote(Atom.to_string(__MODULE__))} #{inspect(cesr_elements)}: must be a list"}
    end

    def from_b64("-" <> unquote(code) <> <<count::binary-size(unquote(text_size)), rest::binary>>) do
      case Base64Indicies.deserialize_value_in_b64_index_scheme(count) do
        # split the stream for the current count code and the rest
        {:ok, 0} -> {{:ok, %__MODULE__{cesr_elements: []}}, rest}
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

    def from_binary(<<unquote(bits_of_code)::bitstring, count::bitstring-size(unquote(text_size)*6), rest::bitstring>>) do
      case calc_padding_to_byte_boundary(count) do
        # split the stream for the current count code and the rest
        0 -> {{:ok, struct(__MODULE__, %{cesr_elements: []})}, rest}
        numerical_value_of_count -> 
          <<count_code_bytes::binary-size(numerical_value_of_count * 3), rest_of_stream::binary>> = rest
          case consume_count_code_B(count_code_bytes, [], unquote(consumption_func)) do
            {:ok, cnt_cd_elements} ->  {{:ok, %__MODULE__{cesr_elements: cnt_cd_elements}}, rest_of_stream}
            {:error, err_msg} -> {:error, err_msg}
          end
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
    defp consume_count_code_T(<<>>, acc, _consumption_func), do: {:ok, Enum.reverse(acc)}
    # transition
    defp consume_count_code_T(count_code_bytes, acc, consumption_func) do
      case consumption_func.(count_code_bytes, :b64) do
        {{:ok, elements}, rest} -> consume_count_code_T(rest, elements ++ acc, consumption_func)
        :notfound -> {:error, "count code not found"}
        {:error, err_msg} -> {:error, err_msg}
      end
    end

    # termination
    defp consume_count_code_B(<<>>, acc, _consumption_func), do: {:ok, Enum.reverse(acc)}
    # transition
    defp consume_count_code_B(count_code_bytes, acc, consumption_func) do
      case consumption_func.(count_code_bytes, :binary) do
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

  defimpl Cesr.CesrElement, for: module_name do
    def to_b64(cesr_element), do: unquote(module_name).to_b64(cesr_element)
    def to_binary(cesr_element), do: unquote(module_name).to_binary(cesr_element)
    def properties(_cesr_element), do: unquote(module_name).properties()
  end
end

defmodule Cesr.CountCodeKERIv2.CountCodeValidationUtilities do
  @moduledoc """
    These will be the validation functions for count codes that utilize the keri element groupings.

    NOTE: due to ambiguity in how the specs are written, keripy has chosen to allow count codes containing
    no elements.  So for all functions, empty list should return true.
  """
  #alias Cesr.CodeTable.KeriElementGroupings

  def trivial?([]), do: true
  def trivial?(list_of_cesr_elements) 
    when is_list(list_of_cesr_elements) 
  do
    true
  end
end

defmodule Cesr.CountCodeKERIv2.CountCodeConsumptionUtilities do
  @moduledoc """
  These will be the consumption functions for count codes that utilize
  the keri element groupings.

  Each function is a step-function that reads off the primitives
  suggested by the semantics and returns the typical recursive call
  tuple pattern we have elsewhere in the parser (except returning
  multiple elements instead of just one): ie. `{{:ok, elements},
  rest_of_stream}`

  If any issue arises we return `{:error, err_msg}`

  NOTE: due to ambiguity in how the specs are written, keripy has chosen
  to allow count codes containing no elements.  So for all functions,
  empty list should return empty list
  """

  alias Cesr.CodeTable.KeriCodeTableV1
  alias Cesr.CodeTable.KeriCodeTableV2
  alias Cesr.CodeTable.UniversalProtocolGenusTable

  def trivial(cesr_stream, :binary) when is_binary(cesr_stream) do
    case KeriCodeTableV2.get_B(cesr_stream) do
      {{:ok, element}, rest} -> {{:ok, [element]}, rest}
      {:error, err_msg} -> {:error, err_msg}
    end
  end
  def trivial(cesr_stream, :b64) when is_binary(cesr_stream) do
    case KeriCodeTableV2.get_T(cesr_stream) do
      {{:ok, element}, rest} -> {{:ok, [element]}, rest}
      {:error, err_msg} -> {:error, err_msg}
    end
  end

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

end
