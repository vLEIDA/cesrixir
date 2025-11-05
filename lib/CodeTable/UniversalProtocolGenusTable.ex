defmodule Cesr.CodeTable.UniversalProtocolGenusTable do
  # -_AAABAA	KERI/ACDC protocol stack code table at genus AAA and Version 1.00	8	5	8
  def get_T("-_AAABAA" <> <<rest::binary>>), do: {{:ok, :keri_aaabaa}, rest}
  # -_AAACAA	KERI/ACDC protocol stack code table at genus AAA and Version 2.00	8	5	8
  def get_T("-_AAACAA" <> <<rest::binary>>), do: {{:ok, :keri_aaacaa}, rest}
  def get_T("-_" <> <<_rest::binary>>), do: :protocol_genus_not_found
  def get_T(_not_protocol_genus_form) do
    :notprotocol_genus
  end
  def get_B(<<251, 240, 0, 0, 16, 0, rest::binary>>) do
    {{:ok, :keri_aaabaa}, rest}
  end
  def get_B(<<251, 240, 0, 0, 32, 0, rest::binary>>) do
    {{:ok, :keri_aaacaa}, rest}
  end
  def get_B(<<251, 15::size(4), _rest::bitstring>>), do: :protocol_genus_not_found
  def get_B(_not_protocol_genus_form) do
    :notprotocol_genus
  end
end
