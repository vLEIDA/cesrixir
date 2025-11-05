defmodule Cesr do
  alias Cesr.CesrElement
  alias Cesr.CodeTable
  alias Cesr.Version_String_1
  alias Cesr.Version_String_2
  alias Cesr.Utility.CBORUtils
  alias Cesr.Utility.JsonUtils
  alias Cesr.Utility.MessagePackUtils

  require Logger

  @spec consume_stream(binary(), list(), non_neg_integer(),
    :keri_aaabaa | :keri_aaacaa) :: list() | {:error, binary()}
  def consume_stream(stream, acc \\ [], current_byte \\ 0, protocol_genus \\ :keri_aaabaa)
  # No elements no stream
  def consume_stream(stream, [], _current_byte, _protocol_genus) when byte_size(stream) == 0 do
    {:error, "Not enough bytes in cesr stream"}
  end
  # Termination on stream exhaustion
  def consume_stream(stream, acc, _current_byte, _protocol_genus)
    when byte_size(stream) == 0 and length(acc) > 0 
  do
    Enum.reverse(Enum.filter(acc, fn "" -> false; _ -> true end))
  end
  # Entrypoint, accumulator and current_byte both start at zero
  def consume_stream(stream, acc, current_byte, protocol_genus) do
    case consume_element(stream, protocol_genus) do
      {:protocol_genus_switch, new_protocol_genus, rest} -> 
        consume_stream(rest, [new_protocol_genus | acc], byte_size(stream) - byte_size(rest) + current_byte, new_protocol_genus)
      {:ok, element, rest} ->
          consume_stream(rest, [element | acc], byte_size(stream) - byte_size(rest) + current_byte, protocol_genus)
      {:error, message} -> {:error, message}
    end
  end

  def produce_text_stream(list_of_cesr_elements) when is_list(list_of_cesr_elements) do
    _produce_stream(list_of_cesr_elements, :text, [])
  end
  def produce_binary_stream(list_of_cesr_elements) when is_list(list_of_cesr_elements) do
    _produce_stream(list_of_cesr_elements, :binary, [])
  end
  # Field maps
  # Note: version should always be a valid version string in streams used by this function
  defp _produce_stream([event_or_acdc = %OrdMap{tuples: [{"v", version} | _]} | rest_of_stream], stream_domain, acc) do
    {:ok, serialized_ordmap} = case version.kind do
      :json -> JsonUtils.serialize_cesr_json_payload(event_or_acdc, version)
      :cbor -> CBORUtils.serialize_cesr_cbor_payload(event_or_acdc, version)
      :mgpk -> MessagePackUtils.serialize_cesr_mgpk_payload(event_or_acdc, version)
      :cesr -> :not_implemented
    end
    _produce_stream(rest_of_stream, stream_domain, [serialized_ordmap | acc])
  end
  # Count Codes
  defp _produce_stream([cesr_element | rest_of_stream], stream_domain, acc) when is_struct(cesr_element) do
    serialized_element_in_domain = case stream_domain do
      :text -> CesrElement.to_b64(cesr_element)
      :binary -> CesrElement.to_binary(cesr_element)
    end
    _produce_stream(rest_of_stream, stream_domain, [serialized_element_in_domain | acc])
  end
  # Termination
  defp _produce_stream([], _stream_domain, acc) do
    IO.iodata_to_binary(Enum.reverse(acc))
  end

  def consume_element(cesr_stream, protocol_genus \\ :keri_aaabaa)
  def consume_element(cesr_stream, protocol_genus) when byte_size(cesr_stream) >= 1 do
    << first_tritet::3, _::bitstring >> = cesr_stream
    # Each of these have to return {:ok, element, rest_of_stream}
    case sniff_tritet(first_tritet) do
      :annotations -> process_annotations(cesr_stream)
      :cesr_t_cnt_code -> process_T_cnt_code(cesr_stream, protocol_genus)
      :cesr_t_op_code -> process_T_op_code(cesr_stream)
      :json_map -> process_json_map(cesr_stream)
      :mgpk_fixmap -> process_mgpk_fixmap(cesr_stream)
      :cbor_map -> process_cbor_map(cesr_stream)
      :mgpk_16_or_32 -> process_mgpk_16_or_32_map(cesr_stream)
      :cesr_b_cnt_or_op_code -> process_B_cnt_or_op_code(cesr_stream, protocol_genus)
    end
  end
  def consume_element(_, _protocol_genus) do
    Logger.warning("Not enough bytes in cesr element")
    {:error, "Not enough bytes in cesr element"}
  end

  @doc """
    Consume element works on the top level CESR constructs and relies
    explicitly on the cold_start sniffing function.
    However, cesr primitives are also embedded within the field map constructs
    and we'd rather not create a fake stream just to process them.  So this
    helper function reads one primitive off the stream and returns the resulting
    cesr primitive struct (if successful) and an error if not.

    A string containing more than one cesr element is considered an error.
  """
  @spec consume_primitive_T(String.t() | struct(), Version_String_1.t() | Version_String_2.t()) :: {:ok, struct()} | {:notfound, any()} | {:error, any()}
  def consume_primitive_T(cesr_primitive, version \\ Kernel.elem(Version_String_2.new(%{proto: :keri, proto_major: 2, proto_minor: 0, genus_major: 2, genus_minor: 1, kind: :json, size: 0}), 1))
  def consume_primitive_T(cesr_primitive, version) when byte_size(cesr_primitive) >= 4 do
    %version_type{} = version
    result = case version_type do
      Version_String_1 -> CodeTable.KeriCodeTableV1.get_T(cesr_primitive)
      Version_String_2 -> CodeTable.KeriCodeTableV2.get_T(cesr_primitive)
      _ -> {:error, :not_valid_version_string}
    end

    case result do
      {{:ok, cesr_element}, ""} -> {:ok, cesr_element}
      {{:ok, _cesr_element}, anything_else} -> {:error, "Extraneous data: #{anything_else} found in stream, this function can only process one cesr element at a time"}
      :notfound -> {:notfound, "Cesr element not found"}
      {:error, err_msg} -> {:error, err_msg}
    end
  end

  @doc """
  This match_version is for the version string sniffing on the stream.
  """
  @spec match_version(String.t() | Version_String_1.t() | Version_String_2.t())
    :: {:ok, Version_String_1.t() | Version_String_2.t()} | {:error, any()}
  def match_version(%Version_String_1{} = v), do: {:ok, v}
  def match_version(%Version_String_2{} = v), do: {:ok, v}
  def match_version(twenty_five_byte_header) when is_binary(twenty_five_byte_header) do
    case Version_String_2.deserialize(twenty_five_byte_header) do
      {:ok, version_2_string} -> {:ok, version_2_string}
      {:error, _} -> case Version_String_1.deserialize(twenty_five_byte_header) do
        {:ok, version_1_string} -> {:ok, version_1_string}
        {:error, _} -> {:error, "No version matched #{twenty_five_byte_header}"}
      end
    end
  end

  @spec sniff_tritet(0 | 1 | 2 | 3 | 4 | 5 | 6 | 7) :: (:annotations | :cbor_map | :cesr_b_cnt_or_op_code
    | :cesr_t_cnt_code | :cesr_t_op_code | :json_map | :mgpk_16_or_32 | :mgpk_fixmap | :unused)
  defp sniff_tritet(first_tritet) do
      case first_tritet do
        0b000 -> :annotations           # weird list of characters denoting annotations \t, \n, \r
        0b001 -> :cesr_t_cnt_code       # ord("-") [dash]           = 00101101
        0b010 -> :cesr_t_op_code        # ord("_") [underscore]     = 01011111
        0b011 -> :json_map              # ord("{")                  = 01111011
        0b100 -> :mgpk_fixmap           # fixmap starts with 0x8    = 1000
        0b101 -> :cbor_map              # major type 5 starts with  = 10101001
        0b110 -> :mgpk_16_or_32         # all fields start with 0xd = 1101
        0b111 -> :cesr_b_cnt_or_op_code # base64("-") [dash]        = 111110
                                        # base64("_") [underscore]  = 111111
      end
  end

  # Reminder
  # 001100 == 0x30 bc 3*16**1 + 0*16**0 == 48 base 10
  # and 48 base 10 is the code for "M" in base64
  # we need 6 bits to represent a base64 character
  # and we need 3 characters * 8 bits to reach the 24-bit base64 boundary

  # Example 1
  #M      A       A       A
  #001100 00_0000 0000_00 000000 # encoded bits

  # Example 2
  #M      A       A       B
  #001100 00_0000 0000_00 000001 # encoded bits

  # Example 3
  #M      P       _       _
  #001100 00_1111 1111_11 111111 # encoded bits
  #          1111 1111 11 111111

  # Text domain count codes all start with - (dash)
  # Text domain op codes all start with _ (underscore) but aren't defined yet
  # 111110 is the url-safe base64 representation of a dash
  # the first tritet of 111110 is 111, so we go to 0b111 -> :cesr_b_cnt_or_op_code
  # Question: how do we ever get to 0b001 -> :cesr_t_cnt_code?

  # So when '-' (dash, for count codes) is encoded in utf8, it will be 0x2d (decimal 45)
  # which is binary 0b00101101. (In other words, ord("-") == 45.)
  # First 3 bits are 001, which is 0b001 -> :cesr_t_cnt_code
  # next 5 bits are 01101

  # 0b000 -> :unused
  # 0b001 -> :cesr_t_cnt_code         ord("-") [dash]           = 00101101
  # 0b010 -> :cesr_t_op_code          ord("_") [underscore]     = 01011111
  # 0b011 -> :json_map                ord("{")                  = 01111011
  # 0b100 -> :mgpk_fixmap             fixmap starts with 0x8    = 1000
  # 0b101 -> :cbor_map                major type 5 starts with  = 10101001
  # 0b110 -> :mgpk_16_or_32           all fields start with 0xd = 1101
  # 0b111 -> :cesr_b_cnt_or_op_code   base64decode("-")         = 111110
  #                                   base64decode("_")         = 111111

  # T cnt/op
  #  First character is utf8 encoded value ie) '-' is 0x2d (45) == 0b001_01101
  #  First character is utf8 encoded value ie) '_' is 0x5f (95) == 0b010_11111
  # B cnt/op
  #  First character is base64 encoded value ie) '-' is 62 in urlsafe base64 -> 0b111_110
  #  First character is base64 encoded value ie) '_' is 63 in urlsafe base64 -> 0b111_111

  # ord("{") = 123 = 0x7b = 01111011 (padded to 8 bits)
  # first tritet = 0b011 -> :json_map
  # next 5 bits are 11011

  # 1. (cold start) We peek at the stream.  Figure out what domain we're in
  #    If we're in map domain, we get size and read map
  #    If we're in cnt domain:
  #         If we're in text domain we read 4 bytes utf8decode(bytes) -> 4 characters in text domain
  #             process_cnt_code_in_text_domain(4_chars, stream)
  #         If we're in binary domain we read 3 bytes urlsafe_base64decode(bytes) -> 4 characters in text domain
  #             process_cnt_code_in_binary_domain(4_chars, stream)

  # process_cnt_code_in_text_domain(4_chars, stream)
  #    Lookup first two characters of 4_chars and see if we need another 4 bytes
  #         If so get next 4bytes
  #    process_code_against_table_in_text_domain(4_or_8_chars, stream)

  # process_cnt_code_in_binary_domain(4_chars, stream)
  #    Lookup first two characters of 4_chars and see if we need another 3 bytes
  #         If so get next 3bytes -> urlsafe_base64decode(3bytes) -> next_4_chars in text domain
  #    process_code_against_table_in_binary_domain(4_or_8_chars, stream)

  # process_code_against_table_in_text_domain(4_or_8_chars, stream)
  #   num_of_quadlets = get_size_from_table(4_or_8_chars)
  #   quadlets, stream = get_quadlets_from_stream(stream)

  # process_code_against_table_in_binary_domain(4_or_8_chars, stream)
  #   num_of_tritets = get_size_from_table(4_or_8_chars)
  #   tritets, stream = get_tritets_from_stream(stream)

  # while stream
  # if cnt code
  #   size, rest = read_bytes_from_size(size, stream)
  #   cesr_objects = iterate_through_cesr_objects
  #   (optional) check that primitives match semantics of code
  #   return cesr_objects

  # PADDING
  # when converting bytes -> b64, add padding based (ps = # bytes)
  # when converting b64 -> bytes, shift right to drop padding (ps * 2 bits)
  # We calculate ps from https://trustoverip.github.io/tswg-cesr-specification/#pre-padding-before-conversion
  # ps = (3 - (N mod 3)) mod 3) where N is length of message in binary domain?
  # if ps == 1 we bit shift the base64 encoded string right 4 bits
  # if ps == 2 we bit shift the base64 encoded string right 2 bits
  # if ps == 3 we don't bit shift

  # So an example
  # If we have a byte string of length x
  # calculate ps
  # then padded payload == right_shift(Base64(Code), ps_calc) <> Base64(payload of length x)

  # cesr_non_map_element Protocol (reason field maps json, cbor, mgpk aren't included is because they're always in the binary domain)
  # [runtime] (code, payload_raw_bytes) -> f_raw_to_binary() | f_raw_to_b64()
  # [wire]    binary -> f_binary_to_code_raw() | f_binary_to_b64()
  # [wire]    b64 -> f_b64_to_code_raw() | f_b64_to_binary()
  # new() -> construct (code, raw)

  # stream = (Cnt Code (Cnt Code Element Element Element) Element)
  # stream = (1        (2                               ) 1      )
  # stream = (byte slice, (byte slice), byte_slice)

  # maybe we'll need some utility classes to generate and consume primitives or whatever

  # These are the representations
  # Field Maps ordered_map (sizeified, said, map)
  # Primitive (code, raw)
  # Cnt Code (code, _raw, primitives | cnt codes)
  # Op Code - not implemented
  # Indexed Cnt Codes (code, _raw, [primitives | cnt code])

  #   defstruct [:primitive, :cesr_wire_representation, :primitive_data_structure]
  # cesr_wire_representation = text / binary

  # Matter() -> init(qb2 | qb64 | qb64b | code, raw | payload) -> (code, raw, cesr_serializtion, deserialized_payload...)
  #
  # +
  # +    f(string) -> figure out which code -> pad -> return
  # +
  # +    bytestreams
  # +    binary_1 "X"   16-bit  6-bits  2-pad (right-shift 2)   '5A'
  # +    binary_2 "XX"  32-bit 12-bits 1-pad (right-shift 4)   '6A'
  # +    binary_3 "XXX" 48-bit 24-bits 0-pad (no shift)        '4A'
  # +
  # +        4A=code AB=soft-size                                                                                                                                                               +        \x58 = "X"
  # +        "XXX" = 8*3 = 24 bits
  # +        0101 1000 0101 1000 0101 1000 (24-bit boundary, no padding, fine)
  # +    T \x34 \x41 \x41 \x41 -> b64translate -> {000100 000000 000000 000001} <bytestreampayload, 4-bytes>
  # +    B
  # +
  # +    4A AA A byte
  # +
  # +    B1 B2 B3 ... BN 24 bit boundary
  #
  #      For using with Matter class to get examples.
  # +        print("raw:\t{}".format(self.raw))
  # +        print("code:\t{}".format(self.code))
  # +        print("soft:\t{}".format(self.soft))
  # +        print("qb2:\t{}".format(self.qb2))
  # +        print("l(qb2):\t{}".format(len(self.qb2)))
  # +        print("qb64:\t{}".format(self.qb64))
  # +        print("l(64):\t{}".format(len(self.qb64)))
  # +        print()
  # +        if self.code == "4A":
  # +            import pdb; pdb.set_trace()

  # 1. Implement rest of primitives, these are same with CESR 1 and 2
  # 2. Implement count codes cesr 2
  # 3. Implement count codes cesr 1
  # 4. {--AAABAA (v1) --AAACAA (v2)} -> {Parse v2 (fail) -> Parse v1 (fail) -> stream fail}
  # 5. Implement KERI/ACDC etc... (SAID, ACDC, libsodium/crypto bindings, watchers, witnesses)

  # cnt_cd_state -> {field_map, count_cd, primitive, different_genus_protocol}

  # count_code_cesr_element_list = []
  # while count_payload_left
  #   cesr_element, count_payload_left = process_element_or_count_code(count_payload_left)
  #   count_code_cesr_element_list.append(cesr_element)'
  # count_code_cesr_element_listIO

  # Kerilixir
  #   CESR
  #     VERSION STRINGS
  #
  #     UTILS
  #       BASE64
  #       MGPK UTILS
  #       JSON UTILS
  #       CBOR UTILS
  #     CODE TABLES
  #     PRIMITIVES
  #     COUNT CODES
  #   SAID
  #   OOBI
  #   ACDC
  #   SAD PATH
  #   IPEX
  #   KERI
  #     WALLET
  #     OOBI ENDPOINT
  #     IPEX Requests
  #     SIGNING
  #     ENCRYPTING
  #     WITNESSING
  #     WATCHING
  #     AID LOGISTICS

  # Basically we remove whitespace whenever we find it.
  # This function should only be able to be called from a text stream context
  # src/keri/core/streaming denote()
  #
  # Note this isn't in the spec but we can't just remove leading whitespace,
  # keripy actually removes leading white space, an optional pound sign
  # denoting a comment, and then the white space until the next "universal" newline.
  #
  # We split on ["\n", "\n\r", "\r"] because they use splitlines() in keripy
  # which relies on Universal Newlines
  # See: https://docs.python.org/3.3/library/stdtypes.html#str.splitlines
  #      https://docs.python.org/3.3/glossary.html#term-universal-newlines
  #
  # Note: ONLY \t, \n, \r can be used to annotate comments in CESR.  Its hidden in a comment in the CESR spec to quote:
  # Finally, several useful applications of ‘T’ domain encoding of CESR streams for archiving or logging may benefit from annotations.
  # The white space ASCII characters for line feed, carriage return, and tab all have starting tritets of 0b000.
  # So only \t, \n, \r (or the other ASCII characters that happent to start with 0b000 I guess)
  # NOT SPACE
  @spec process_annotations(String.t()) :: {:ok, String.t(), String.t()}
  defp process_annotations(stream) when is_binary(stream) do
    trimmed_string = String.trim_leading(stream)
    stream_wo_comments = case String.starts_with?(trimmed_string, "#") do
      true ->  [_comment, rest_of_stream] = String.split(trimmed_string, ["\n", "\n\r", "\r"], parts: 2)
               rest_of_stream
      false -> trimmed_string
    end
    {:ok, "", stream_wo_comments}
  end

  defp process_T_cnt_code(stream, current_protocol_genus) when byte_size(stream) >= 4 do
    # If we're in text domain we read 4 bytes utf8decode(bytes) -> 4 characters in text domain
    #             process_cnt_code_in_text_domain(4_chars, stream)
    
    # is there a protocol/genus switch?
    keri_genus_protocol = case CodeTable.UniversalProtocolGenusTable.get_T(stream) do
      :protocol_genus_not_found -> :protocol_genus_not_found
      :notprotocol_genus -> {current_protocol_genus, stream}
      {{:ok, new_protocol_genus}, rest} -> {:protocol_genus_switch, new_protocol_genus, rest}
    end

    maybe_t_count_code = case keri_genus_protocol do
      {:keri_aaabaa, stream} -> CodeTable.KeriCodeTableV1.get_T(stream)
      {:keri_aaacaa, stream} -> CodeTable.KeriCodeTableV2.get_T(stream)
      :protocol_genus_not_found -> :protocol_genus_not_found
      {:protocol_genus_switch, _, _} = switch -> switch
    end

    case maybe_t_count_code do
      :notfound -> {:error, "Cnt Code in not found in table"}
      :protocol_genus_not_found -> {:error, "Unknown protocol/genus in stream"}
      {:protocol_genus_switch, _, _} = switch -> switch
      {{:ok, cnt_code_struct_result}, rest_of_stream} -> {:ok, cnt_code_struct_result, rest_of_stream}
      #e -> {:error, "Unexpected Return from looking up Count Code: #{inspect(e)}"}
    end
  end
  defp process_T_cnt_code(stream, _protocol_genus) do
    Logger.warning("Not enough bytes in stream: #{stream}")
    {:error, "Not enough bytes in cesr element"}
  end

  defp process_T_op_code(_stream) do
    Logger.error("Op codes in CESR 2.00 are currently undefined.  Thus not implemented in kerilixir.")
    {:error, "Op Codes not defined"}
  end

  defp process_json_map(stream) do
    try do
      with twenty_five_byte_slice_attempt <- Kernel.binary_part(stream, 0, 25),
        {:ok, version} <- match_version(twenty_five_byte_slice_attempt),
        potential_json_map <- Kernel.binary_part(stream, 0, version.size),
        {:ok, cesr_ordmap} <- JsonUtils.deserialize_cesr_json_payload(potential_json_map)
      do
        cesr_ordmap_w_version = OrdMap.put(cesr_ordmap, "v", version)
        <<_map::binary-size(version.size), rest_of_stream::binary>> = stream
        {:ok, cesr_ordmap_w_version, rest_of_stream}
      else
        {:error, err_msg} -> {:error, "Error in processing json map: #{err_msg}"}
      end
    rescue
      ArgumentError -> {:error, "Not enough input to read version string"}
    end
  end

  # Process Mgpk fixmap is the same as dynamic map in mgpk.  So we just call that function.
  defp process_mgpk_fixmap(stream) do
    process_mgpk_map(stream)
  end

  defp process_cbor_map(<<twenty_five_byte_slice::binary-size(25), _rest::binary>> = stream) do
    try do
      with {:ok, version} <- match_version(twenty_five_byte_slice),
        <<potential_cbor_map::binary-size(version.size), rest_of_stream::binary>> <- stream,
        {:ok, cesr_ordmap} <- CBORUtils.deserialize_cesr_cbor_payload(potential_cbor_map)
      do
        # We do this just to avoid unserializing the version again
        cesr_ordmap_w_version = OrdMap.put(cesr_ordmap, "v", version)
        {:ok, cesr_ordmap_w_version, rest_of_stream}
      else
        {:error, err_msg} -> {:error, "Error in processing CBOR map: #{err_msg}"}
      end
    rescue 
      MatchError -> {:error, "Not enough bytes in stream corresponding to version size"}
    end
  end
  defp process_cbor_map(_stream), do: {:error, "Not enough input to read version string"}

  # Functionally the same as processing a fixmap so we call the mgpk parsing function here
  defp process_mgpk_16_or_32_map(stream) do
    process_mgpk_map(stream)
  end

  # In the binary domain 0b111 tritet on head of stream can go to 0b111110 "-" cnt code or 0b111111 "_" op code
  # so we switch here based on both cases
  # -cnt code
  defp process_B_cnt_or_op_code(<<62::size(6), _rest::bitstring>> = stream, current_protocol_genus) do
    # is there a protocol/genus switch?
    keri_genus_protocol = case CodeTable.UniversalProtocolGenusTable.get_B(stream) do
      :protocol_genus_not_found -> :protocol_genus_not_found
      :notprotocol_genus -> {current_protocol_genus, stream}
      {{:ok, new_protocol_genus}, rest} -> {:protocol_genus_switch, new_protocol_genus, rest}
    end

    maybe_b_count_code = case keri_genus_protocol do
      {:keri_aaabaa, stream} -> CodeTable.KeriCodeTableV1.get_B(stream)
      {:keri_aaacaa, stream} -> CodeTable.KeriCodeTableV2.get_B(stream)
      :protocol_genus_not_found -> :protocol_genus_not_found
      {:protocol_genus_switch, _, _} = switch -> switch
    end

    case maybe_b_count_code do
      :notfound -> {:error, "Cnt Code in not found in table"}
      :protocol_genus_not_found -> {:error, "Unknown protocol/genus in stream"}
      {:protocol_genus_switch, _, _} = switch -> switch
      {{:ok, cnt_code_struct_result}, rest_of_stream} -> {:ok, cnt_code_struct_result, rest_of_stream}
      #e -> {:error, "Unexpected Return from looking up Count Code: #{inspect(e)}"}
    end
  end
  # -op code
  defp process_B_cnt_or_op_code(<<63::size(6), _rest::bitstring>>, _current_protocol_genus) do
    Logger.warning("Op codes in CESR 2.00 are currently undefined.  Thus not implemented in kerilixir.")
    {:error, "Op Codes not defined"}
  end

  defp process_mgpk_map(stream) do
    try do
      with twenty_five_byte_slice_attempt <- Kernel.binary_part(stream, 0, 25),
        {:ok, version} <- match_version(twenty_five_byte_slice_attempt),
        potential_mgpk_map <- Kernel.binary_part(stream, 0, version.size),
        {:ok, cesr_ordmap} <- MessagePackUtils.deserialize_cesr_mgpk_payload(potential_mgpk_map)
      do
        cesr_ordmap_w_version = OrdMap.put(cesr_ordmap, "v", version)
        <<_map::binary-size(version.size), rest_of_stream::binary>> = stream
        {:ok, cesr_ordmap_w_version, rest_of_stream}
      else
        {:error, err_msg} -> {:error, "Error in processing mgpk fixmap: #{err_msg}"}
      end
    rescue
      _ in ArgumentError -> {:error, "Not enough input to read size from version string"}
    end
  end
end

# THIS IS A COMPLETE HACK.  Def figure out how to remove this and fix all the events serializing/deserializing to the right elements
defimpl Cesr.CesrElement, for: BitString do
  def to_b64(cesr_element), do: cesr_element
  def to_binary(cesr_element), do: cesr_element
  def properties(cesr_element), do: %{code: :str, short_name: :str, long_name: <<"String">>, text_size: byte_size(cesr_element)}
end
