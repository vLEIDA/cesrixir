defmodule Kerilixir.SADPathTests do
  alias Cesr.SadPath

  use ExUnit.Case, async: true

  # Example taken from keripy test_cesr_examples

  setup do
    [sad: OrdMap.new([
      {"v", "ACDCCAACAAJSONAAIe."},
      {"t", "acm"},
      {"d", "EO3117lnAbjDt66qe2PtgHooXKAYQT_C6SIbESMcJ5lN"},
      {"i", "EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYVXe9isaP5SW"},
      {"s", "EGU_SHY-8ywNBJOqPKHr4sXV9tOtOwpYzYOM63_zUCDW"},
      {"a", OrdMap.new([
        {"d", "ED1wMKzV72L7YI1yJ3NXlClPUgvEerw4jRocOYxaZGtH"},
        {"i", "ECsGDKWAYtHBCkiDrzajkxs3Iw2g-dls3bLUsRP4yVdT"},
        {"dt", "2025-06-09T17:35:54.169967+00:00"},
        {"personal", OrdMap.new([
          {"name", "John Doe"},
          {"home", "Atlanta"}
        ])},
        {"p", [
          OrdMap.new([
            {"ref0", OrdMap.new([
              {"name", "Amy"},
              {"i", "ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz"}
            ])}
          ]),
          OrdMap.new([
            {"ref1", OrdMap.new([
              {"name", "Bob"},
              {"i", "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf"}
            ])}
          ])
        ]}
      ])}
    ])]
  end

  test "Test sadpath happy", context do
    sad = context[:sad]
    assert SadPath.resolve_path(sad, "-") == {:ok, sad}
    assert SadPath.resolve_path(sad, "-a-personal") == {:ok, OrdMap.new([{"name", "John Doe"}, {"home", "Atlanta"}])}
    assert SadPath.resolve_path(sad, "-5-3") == {:ok, OrdMap.new([{"name", "John Doe"}, {"home", "Atlanta"}])}
    assert SadPath.resolve_path(sad, "-5-3-name") == {:ok, "John Doe"}
    assert SadPath.resolve_path(sad, "-a-personal-1") == {:ok, "Atlanta"}
    assert SadPath.resolve_path(sad, "-a-p-1-0") == {:ok, OrdMap.new([{"name", "Bob"}, {"i", "ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf"}])}
    assert SadPath.resolve_path(sad, "-a-p-0-0-name") == {:ok, "Amy"}
    assert SadPath.resolve_path(sad, "-a-p-0-ref0-i") == {:ok, "ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz"}
  end

  test "Test sadpath sad", context do
    sad = context[:sad]
    assert SadPath.resolve_path(sad, "") == {:error, "Sad path malformed, no dashes "}
    assert SadPath.resolve_path(sad, "--") == {:error, "There is no field or idx @ \"\" in %OrdMap{tuples: [{\"v\", \"ACDCCAACAAJSONAAIe.\"}, {\"t\", \"acm\"}, {\"d\", \"EO3117lnAbjDt66qe2PtgHooXKAYQT_C6SIbESMcJ5lN\"}, {\"i\", \"EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYVXe9isaP5SW\"}, {\"s\", \"EGU_SHY-8ywNBJOqPKHr4sXV9tOtOwpYzYOM63_zUCDW\"}, {\"a\", %OrdMap{tuples: [{\"d\", \"ED1wMKzV72L7YI1yJ3NXlClPUgvEerw4jRocOYxaZGtH\"}, {\"i\", \"ECsGDKWAYtHBCkiDrzajkxs3Iw2g-dls3bLUsRP4yVdT\"}, {\"dt\", \"2025-06-09T17:35:54.169967+00:00\"}, {\"personal\", %OrdMap{tuples: [{\"name\", \"John Doe\"}, {\"home\", \"Atlanta\"}]}}, {\"p\", [%OrdMap{tuples: [{\"ref0\", %OrdMap{tuples: [{\"name\", \"Amy\"}, {\"i\", \"ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz\"}]}}]}, %OrdMap{tuples: [{\"ref1\", %OrdMap{tuples: [{\"name\", \"Bob\"}, {\"i\", \"ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf\"}]}}]}]}]}}]}"}
    assert SadPath.resolve_path(sad, "-a-1-") == {:error, "Either path malformed: [\"\"] or \"ECsGDKWAYtHBCkiDrzajkxs3Iw2g-dls3bLUsRP4yVdT\" not list or map that aligns with that path"}
    assert SadPath.resolve_path(sad, "-panda") == {:error, "There is no field or idx @ \"panda\" in %OrdMap{tuples: [{\"v\", \"ACDCCAACAAJSONAAIe.\"}, {\"t\", \"acm\"}, {\"d\", \"EO3117lnAbjDt66qe2PtgHooXKAYQT_C6SIbESMcJ5lN\"}, {\"i\", \"EEDGM_DvZ9qFEAPf_FX08J3HX49ycrVvYVXe9isaP5SW\"}, {\"s\", \"EGU_SHY-8ywNBJOqPKHr4sXV9tOtOwpYzYOM63_zUCDW\"}, {\"a\", %OrdMap{tuples: [{\"d\", \"ED1wMKzV72L7YI1yJ3NXlClPUgvEerw4jRocOYxaZGtH\"}, {\"i\", \"ECsGDKWAYtHBCkiDrzajkxs3Iw2g-dls3bLUsRP4yVdT\"}, {\"dt\", \"2025-06-09T17:35:54.169967+00:00\"}, {\"personal\", %OrdMap{tuples: [{\"name\", \"John Doe\"}, {\"home\", \"Atlanta\"}]}}, {\"p\", [%OrdMap{tuples: [{\"ref0\", %OrdMap{tuples: [{\"name\", \"Amy\"}, {\"i\", \"ECmiMVHTfZIjhA_rovnfx73T3G_FJzIQtzDn1meBVLAz\"}]}}]}, %OrdMap{tuples: [{\"ref1\", %OrdMap{tuples: [{\"name\", \"Bob\"}, {\"i\", \"ECWJZFBtllh99fESUOrBvT3EtBujWtDKCmyzDAXWhYmf\"}]}}]}]}]}}]}"}
    assert SadPath.resolve_path(sad, "panda") == {:error, "Sad path malformed panda"}
  end

  test "Sadpath bullshit" do
    # The spec doesn't say what to do when a sad path ambiguously refers to
    # both an index and a key name. For example, "-1" could refer to the entry
    # at index 1 ("second entry") or to the entry with key "1" ("string 1") or
    # perhaps the entry with key 1 ("integer 1")? The keripy code treats it as
    # an index in such cases so we'll go with that.
    badsad = OrdMap.new([
      { "first", "first entry"},
      {"second", "second entry"},
      { "third", "third entry"},
      {     "0", "string 0"},
      {     "1", "string 1"},
      {     "2", "string 2"},
      {       0, "integer 0"},
      {       1, "integer 1"},
      {       2, "integer 2"}
    ])
    assert SadPath.resolve_path(badsad, "-0")      == {:ok, "first entry"}
    assert SadPath.resolve_path(badsad, "-first")  == {:ok, "first entry"}
    assert SadPath.resolve_path(badsad, "-1")      == {:ok, "second entry"}
    assert SadPath.resolve_path(badsad, "-second") == {:ok, "second entry"}
    assert SadPath.resolve_path(badsad, "-2")      == {:ok, "third entry"}
    assert SadPath.resolve_path(badsad, "-third")  == {:ok, "third entry"}
    assert SadPath.resolve_path(badsad, "-3")      == {:ok, "string 0"}
    assert SadPath.resolve_path(badsad, "-x")      == {:error, "There is no field or idx @ \"x\" in %OrdMap{tuples: [{\"first\", \"first entry\"}, {\"second\", \"second entry\"}, {\"third\", \"third entry\"}, {\"0\", \"string 0\"}, {\"1\", \"string 1\"}, {\"2\", \"string 2\"}, {0, \"integer 0\"}, {1, \"integer 1\"}, {2, \"integer 2\"}]}"}
    assert SadPath.resolve_path(badsad, "-8")      == {:ok, "integer 2"}
    assert SadPath.resolve_path(badsad, "-10")     == {:error, "There is no field or idx @ \"10\" in %OrdMap{tuples: [{\"first\", \"first entry\"}, {\"second\", \"second entry\"}, {\"third\", \"third entry\"}, {\"0\", \"string 0\"}, {\"1\", \"string 1\"}, {\"2\", \"string 2\"}, {0, \"integer 0\"}, {1, \"integer 1\"}, {2, \"integer 2\"}]}"}
  end
end
