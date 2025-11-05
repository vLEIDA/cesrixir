defmodule Cesr.Version_String_2_Test do
  alias Cesr.Version_String_2

  use ExUnit.Case, async: true

  test "Version 2 schemes deserialize correctly" do
    # This string actually can never occur in our scheme
    assert {:ok, %Version_String_2{proto: :keri, proto_major: 1, proto_minor: 0, 
                                   genus_major: 1, genus_minor: 0, kind: :json, size: 0}} ==
      Version_String_2.deserialize("KERIBAABAAJSONAAAA.")
    assert {:ok, %Version_String_2{proto: :keri, proto_major: 2, proto_minor: 0, 
                                   genus_major: 2, genus_minor: 0, kind: :cbor, size: 0}} ==
      Version_String_2.deserialize("KERICAACAACBORAAAA.")
   assert {:ok, %Version_String_2{proto: :keri, proto_major: 2, proto_minor: 0, 
                                   genus_major: 2, genus_minor: 0, kind: :mgpk, size: 0}} ==
      Version_String_2.deserialize("KERICAACAAMGPKAAAA.")
  end

  test "Bad Version 2 schemes don't deserialize without errors" do
    # Bad Protocol
    assert {:error, <<"Failed to deserialize: %{", _::binary>>} = Version_String_2.deserialize("BADPBAABAAJSONAAAA.")
    # Bad Kind
    assert {:error, "Potential atom: BADK not valid in kerilixir"} == Version_String_2.deserialize("KERIBAABAABADKAAAA.")
    # Bad Version
    assert {:error, "Failed to deserialize"} == Version_String_2.deserialize("KERI+++JSONAAAA.")
    # Bad size
    assert {:error, "Error base64url decoding ++++"} == Version_String_2.deserialize("KERIBAABAAJSON++++.")
  end

  test "Version 2 schemes serialize without errors" do
    assert Version_String_2.serialize(%Version_String_2{proto: :keri, proto_major: 1, proto_minor: 0, 
                                                        genus_major: 1, genus_minor: 0, kind: :json, size: 0}) == 
      {:ok, "KERIBAABAAJSONAAAA."} 
    assert Version_String_2.serialize(%Version_String_2{proto: :acdc, proto_major: 63, proto_minor: 4095,
                                                        genus_major: 63, genus_minor: 4095, kind: :cbor, size: 16_777_215}) ==
      {:ok, "ACDC______CBOR____."}
  end

  test "Version 2 structs can be constructed with new" do
    assert Version_String_2.new(%{proto: :keri, proto_major: 1, proto_minor: 0,
                                  genus_major: 1, genus_minor: 0, kind: :json, size: 0}) ==
      {:ok, %Version_String_2{proto: :keri, proto_major: 1, proto_minor: 0,
                              genus_major: 1, genus_minor: 0, kind: :json, size: 0}}
  end

  test "Bad Version 2 input cannot be constructed with new" do
    # Bad protocol
    assert {:error, _} = Version_String_2.new(%{proto: :badp, proto_major: 1, proto_minor: 0,
                              genus_major: 1, genus_minor: 0, kind: :json, size: 0})
    # Bad major
    assert {:error, _} = Version_String_2.new(%{proto: :keri, proto_major: 99, proto_minor: 0,
                                                genus_major: 1, genus_minor: 0, kind: :json, size: 0})
    # Bad minor
    assert {:error, _} = Version_String_2.new(%{proto: :keri, proto_major: 1, proto_minor: 5000,
                                                genus_major: 1, genus_minor: 0, kind: :json, size: 0})
    # Bad kind
    assert {:error, _} = Version_String_2.new(%{proto: :keri, proto_major: 1, proto_minor: 0,
                                                genus_major: 1, genus_minor: 0, kind: :xml_, size: 0})
    # Bad size
    assert {:error, _} = Version_String_2.new(%{proto: :keri, proto_major: 1, proto_minor: 0,
                                                genus_major: 1, genus_minor: 0, kind: :json, size: -1})
  end
end
