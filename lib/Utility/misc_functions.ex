defmodule Cesr.Utilities.MiscellaneousFunctions do
  # For removing leading 0 bytes from binary
  def remove_leading_nulls(<<0, rest::binary>>), do: remove_leading_nulls(rest)
  def remove_leading_nulls(binary), do: binary

  @doc """
  Order of fields (both KEL events and Routed Message fields)
  """
  @spec order_fields(struct()) :: OrdMap.t()
  def order_fields(event) do
    # We checked that KEL fields and routed message fields don't overlap
    all_event_fields = [
      {"v",  :v_version},
      {"t",  :t_eventType},
      {"d",  :d_digest},
      {"i",  :i_issuer},
      {"ri", :r_receiverIdentifier}, # Routed Message
      {"x",  :x_exchangeIdentifier}, # Routed Message
      {"s",  :s_sequenceNumber},
      {"p",  :p_previousDigest}, # Kel and Routed Message
      {"dt", :dt_dateTime}, # Routed Message
      {"r",  :r_route}, # Routed Message
      {"rr", :rr_returnRoute}, # Routed Message
      {"q",  :q_query}, # Routed Message
      {"kt", :kt_signingThreshold},
      {"k",  :k_publicKey},
      {"nt", :nt_nextThreshold},
      {"n",  :n_nextRotationKeys},
      {"bt", :bt_backerThreshold},
      {"b",  :b_backers},
      {"br", :br_backerRemovals},
      {"ba", :ba_backerAppends},
      {"c",  :c_configOptions},
      {"a",  :a_seals},
      {"a",  :a_attribute}, # Routed Message
      {"di", :di_delegator_aid}
    ]

    all_event_fields
      |> Enum.filter(fn {_short_name, long_name}
          -> Map.has_key?(event, long_name) end)
      |> Enum.map(fn {short_name, long_name}
          -> {short_name, Map.get(event, long_name)} end)
      |> OrdMap.new
  end

  def get_module_for_field_map_type(:json), do: {:ok, Cesr.Utility.JsonUtils}
  def get_module_for_field_map_type(:mgpk), do: {:ok, Cesr.Utility.MessagePackUtils}
  def get_module_for_field_map_type(:cbor), do: {:error, :cbor_field_map_not_implemented}
  def get_module_for_field_map_type(:cesr), do: {:error, :cesr_field_map_not_implemented}
  def get_module_for_field_map_type(_),     do: {:error, :not_valid_field_map_type}
end
