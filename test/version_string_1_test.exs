defmodule Cesr.Version_String_1_Test do
  alias Cesr.Version_String_1

  use ExUnit.Case, async: true

  test "Version 1 schemes deserialize correctly" do
    assert {:ok, %Version_String_1{proto: :keri, major: 1, minor: 0, kind: :json, size: 0}} ==
      Version_String_1.deserialize("KERI10JSON000000_")
    assert {:ok, %Version_String_1{proto: :keri, major: 1, minor: 0, kind: :cbor, size: 0}} ==
      Version_String_1.deserialize("KERI10CBOR000000_")
    assert {:ok, %Version_String_1{proto: :keri, major: 1, minor: 0, kind: :mgpk, size: 0}} ==
      Version_String_1.deserialize("KERI10MGPK000000_")
  end

  test "Bad Version 1 schemes don't deserialize without errors" do
    # Bad Protocol
    assert {:error, "Protocol BADP not a valid protocol"} == Version_String_1.deserialize("BADP10JSON000000_")
    # Bad Kind
    assert {:error, "Kind BADK not a valid serialization"} == Version_String_1.deserialize("KERI10BADK000000_")
    # Bad Version
    assert {:error, "Version 1 Regular Expression didn't match against KERI++JSON000000_"} == Version_String_1.deserialize("KERI++JSON000000_")
    # Bad size
    assert {:error, "Version 1 Regular Expression didn't match against KERI10JSON++++++_"} ==
      Version_String_1.deserialize("KERI10JSON++++++_")
  end

  test "Version 1 schemes serialize without errors" do
    assert Version_String_1.serialize(%Version_String_1{proto: :keri, major: 1, minor: 0, kind: :json, size: 0}) ==
      {:ok, "KERI10JSON000000_"}
    assert Version_String_1.serialize(%Version_String_1{proto: :acdc, major: 15, minor: 15, kind: :cbor, size: 16_777_215}) ==
      {:ok, "ACDCffCBORffffff_"}
  end

  test "Version 1 structs can be constructed with new" do
    assert Version_String_1.new(%{proto: :keri, major: 1, minor: 0, kind: :json, size: 0}) ==
      {:ok, %Version_String_1{proto: :keri, major: 1, minor: 0, kind: :json, size: 0}}
  end

  test "Bad Version 1 input cannot be constructed with new" do
    # Bad protocol
    assert {:error, _} = Version_String_1.new(%{proto: :badp, major: 1, minor: 0, kind: :json, size: 0})
    # Bad major
    assert {:error, _} = Version_String_1.new(%{proto: :keri, major: 99, minor: 0, kind: :json, size: 0})
    # Bad minor
    assert {:error, _} = Version_String_1.new(%{proto: :keri, major: 1, minor: 10000, kind: :json, size: 0})
    # Bad kind
    assert {:error, _} = Version_String_1.new(%{proto: :keri, major: 1, minor: 0, kind: :xml_, size: 0})
    # Bad size
    assert {:error, _} = Version_String_1.new(%{proto: :keri, major: 1, minor: 0, kind: :json, size: -1})
  end
end
