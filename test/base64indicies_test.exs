defmodule Cesr.Utility.Base64IndiciesTest do
  import Cesr.Utility.Base64Indicies

  use ExUnit.Case, async: true

  test "Base64 index for char works" do
    assert get_b64_index_for_char("A") == 0
    assert get_b64_index_for_char("B") == 1
    assert get_b64_index_for_char("C") == 2
    assert get_b64_index_for_char("D") == 3
    assert get_b64_index_for_char("E") == 4
    assert get_b64_index_for_char("F") == 5
    assert get_b64_index_for_char("G") == 6
    assert get_b64_index_for_char("H") == 7
    assert get_b64_index_for_char("I") == 8
    assert get_b64_index_for_char("J") == 9
    assert get_b64_index_for_char("K") == 10
    assert get_b64_index_for_char("L") == 11
    assert get_b64_index_for_char("M") == 12
    assert get_b64_index_for_char("N") == 13
    assert get_b64_index_for_char("O") == 14
    assert get_b64_index_for_char("P") == 15
    assert get_b64_index_for_char("Q") == 16
    assert get_b64_index_for_char("R") == 17
    assert get_b64_index_for_char("S") == 18
    assert get_b64_index_for_char("T") == 19
    assert get_b64_index_for_char("U") == 20
    assert get_b64_index_for_char("V") == 21
    assert get_b64_index_for_char("W") == 22
    assert get_b64_index_for_char("X") == 23
    assert get_b64_index_for_char("Y") == 24
    assert get_b64_index_for_char("Z") == 25
    assert get_b64_index_for_char("a") == 26
    assert get_b64_index_for_char("b") == 27
    assert get_b64_index_for_char("c") == 28
    assert get_b64_index_for_char("d") == 29
    assert get_b64_index_for_char("e") == 30
    assert get_b64_index_for_char("f") == 31
    assert get_b64_index_for_char("g") == 32
    assert get_b64_index_for_char("h") == 33
    assert get_b64_index_for_char("i") == 34
    assert get_b64_index_for_char("j") == 35
    assert get_b64_index_for_char("k") == 36
    assert get_b64_index_for_char("l") == 37
    assert get_b64_index_for_char("m") == 38
    assert get_b64_index_for_char("n") == 39
    assert get_b64_index_for_char("o") == 40
    assert get_b64_index_for_char("p") == 41
    assert get_b64_index_for_char("q") == 42
    assert get_b64_index_for_char("r") == 43
    assert get_b64_index_for_char("s") == 44
    assert get_b64_index_for_char("t") == 45
    assert get_b64_index_for_char("u") == 46
    assert get_b64_index_for_char("v") == 47
    assert get_b64_index_for_char("w") == 48
    assert get_b64_index_for_char("x") == 49
    assert get_b64_index_for_char("y") == 50
    assert get_b64_index_for_char("z") == 51
    assert get_b64_index_for_char("0") == 52
    assert get_b64_index_for_char("1") == 53
    assert get_b64_index_for_char("2") == 54
    assert get_b64_index_for_char("3") == 55
    assert get_b64_index_for_char("4") == 56
    assert get_b64_index_for_char("5") == 57
    assert get_b64_index_for_char("6") == 58
    assert get_b64_index_for_char("7") == 59
    assert get_b64_index_for_char("8") == 60
    assert get_b64_index_for_char("9") == 61
    assert get_b64_index_for_char("-") ==  62
    assert get_b64_index_for_char("_") ==  63
  end

  test "Calculate deserialize b64 version works" do
    assert {:ok, 0} = deserialize_value_in_b64_index_scheme("AA")
    assert {:ok, 4095} = deserialize_value_in_b64_index_scheme("__")
    assert {:ok, 0} = deserialize_value_in_b64_index_scheme("AAAA")
    assert {:ok, 16_777_215} = deserialize_value_in_b64_index_scheme("____")
    assert {:error, _} = deserialize_value_in_b64_index_scheme("??")
    assert {:error, _} = deserialize_value_in_b64_index_scheme("")
  end

  test "Calculate serialize b64 works" do
    assert {:ok, "AA"} = serialize_value_in_b64_index_scheme(0, 2)
    assert {:ok, "__"} = serialize_value_in_b64_index_scheme(4095, 2)
    assert {:ok, "AAAA"} = serialize_value_in_b64_index_scheme(0, 4)
    assert {:ok, "____"} = serialize_value_in_b64_index_scheme(16_777_215, 4)
    assert {:error, _} = serialize_value_in_b64_index_scheme(-1, 1)
    assert {:error, _} = serialize_value_in_b64_index_scheme(4096, 2)
  end

  test "Calculate bits of b64 code works" do
    assert {:ok, << 0b111000_000000::size(12) >>} == bits_of_b64_representation("4A")
    assert {:ok, << 0b111011_000000_000000_000000::size(24) >>} == bits_of_b64_representation("7AAA")
  end

  test "Calculate bad bits of b64 code don't work" do
    assert {:error, _} = bits_of_b64_representation(")")
    assert {:error, _} = bits_of_b64_representation("")
    assert {:error, _} = bits_of_b64_representation(:nil)
    assert {:error, _} = bits_of_b64_representation(1)
  end
end
