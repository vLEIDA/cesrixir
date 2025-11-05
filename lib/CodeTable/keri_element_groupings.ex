defmodule Cesr.CodeTable.KeriElementGroupings do
  @moduledoc """
  KERI has a master table of CESR elements defined in the CESR spec but then a bunch of different "groupings" of these elements
  within the count code semantics (especially in KERI v1 protocol) that you just kind of have to know (or read keripy) to understand.

  This module is meant to provide functions similar to what the Codexes do (which do the groupings in keripy).
  """
  @type version_string() :: Kerilixir.Version_String_1.t() | Kerilixir.Version_String_2.t()

  @type kel_event() :: Kerilixir.Keri.InceptionEvent.t() |
                       Kerilixir.Keri.DelegatedInceptionEvent.t() |
                       Kerilixir.Keri.RotationEvent.t() |
                       Kerilixir.Keri.DelegatedRotationEvent.t() |
                       Kerilixir.Keri.InteractionEvent.t()

  @type routed_message() :: Kerilixir.Keri.RoutedEvents.Bare.t() |
                            Kerilixir.Keri.RoutedEvents.ExchangeContinuation.t() |
                            Kerilixir.Keri.RoutedEvents.ExchangeInception.t() |
                            Kerilixir.Keri.RoutedEvents.Prod.t() |
                            Kerilixir.Keri.RoutedEvents.Query.t() |
                            Kerilixir.Keri.RoutedEvents.Reply.t()

  @type indexed_signature() ::
    Cesr.Primitive.Indexes.IDX_A_Ed25519_Sig.t() |
    Cesr.Primitive.Indexes.IDX_B_Ed25519_Crt_Sig.t() |
    Cesr.Primitive.Indexes.IDX_C_ECDSA_256k1_Sig.t() |
    Cesr.Primitive.Indexes.IDX_D_ECDSA_256k1_Crt_Sig.t() |
    Cesr.Primitive.Indexes.IDX_E_ECDSA_256r1_Sig.t() |
    Cesr.Primitive.Indexes.IDX_F_ECDSA_256r1_Crt_Sig.t() |
    Cesr.Primitive.Indexes.IDX_0A_Ed448_Sig.t() |
    Cesr.Primitive.Indexes.IDX_0B_Ed448_Crt_Sig.t() |
    Cesr.Primitive.Indexes.IDX_2A_Ed25519_Big_Sig.t() |
    Cesr.Primitive.Indexes.IDX_2B_Ed25519_Big_Crt_Sig.t() |
    Cesr.Primitive.Indexes.IDX_2C_ECDSA_256k1_Big_Sig.t() |
    Cesr.Primitive.Indexes.IDX_2D_ECDSA_256k1_Big_Crt_Sig.t() |
    Cesr.Primitive.Indexes.IDX_2E_ECDSA_256r1_Big_Sig.t() |
    Cesr.Primitive.Indexes.IDX_2F_ECDSA_256r1_Big_Crt_Sig.t() |
    Cesr.Primitive.Indexes.IDX_3A_Ed448_Big_Sig.t() |
    Cesr.Primitive.Indexes.IDX_3B_Ed448_Big_Crt_Sig.t()

  @doc """
    All primitives that can be used as an index (idx)
  """
  defdelegate all_indexes, to: Cesr.CodeTable.KeriIndexCodeTable
  defdelegate is_index?(cesr_index_element), to: Cesr.CodeTable.KeriIndexCodeTable

  @type digest() ::
          Cesr.Primitive.CD_E_Blake3_256.t()
          | Cesr.Primitive.CD_F_Blake2b_256.t()
          | Cesr.Primitive.CD_G_Blake2s_256.t()
          | Cesr.Primitive.CD_H_SHA3_256.t()
          | Cesr.Primitive.CD_I_SHA2_256.t()
          | Cesr.Primitive.CD_0D_Blake3_512_Digest.t()
          | Cesr.Primitive.CD_0E_Blake2b_512_Digest.t()
          | Cesr.Primitive.CD_0F_SHA3_512_Digest.t()
          | Cesr.Primitive.CD_0G_SHA2_512_Digest.t()
          | Cesr.Primitive.DummySaidDigest.t()

  @type digest_atom() ::
          Cesr.Primitive.CD_E_Blake3_256
          | Cesr.Primitive.CD_F_Blake2b_256
          | Cesr.Primitive.CD_G_Blake2s_256
          | Cesr.Primitive.CD_H_SHA3_256
          | Cesr.Primitive.CD_I_SHA2_256
          | Cesr.Primitive.CD_0D_Blake3_512_Digest
          | Cesr.Primitive.CD_0E_Blake2b_512_Digest
          | Cesr.Primitive.CD_0F_SHA3_512_Digest
          | Cesr.Primitive.CD_0G_SHA2_512_Digest
          | Cesr.Primitive.DummySaidDigest

  @doc """
    All primitives that can be used as a digest (dig)
  """
  def get_all_digests,
    do: [
      Cesr.Primitive.CD_E_Blake3_256,
      Cesr.Primitive.CD_F_Blake2b_256,
      Cesr.Primitive.CD_G_Blake2s_256,
      Cesr.Primitive.CD_H_SHA3_256,
      Cesr.Primitive.CD_I_SHA2_256,
      Cesr.Primitive.CD_0D_Blake3_512_Digest,
      Cesr.Primitive.CD_0E_Blake2b_512_Digest,
      Cesr.Primitive.CD_0F_SHA3_512_Digest,
      Cesr.Primitive.CD_0G_SHA2_512_Digest
    ]

  def is_digest?(%mod_name{} = cesr_digest_element) 
    when is_struct(cesr_digest_element) 
  do
    Enum.member?(get_all_digests(), mod_name)
  end
  def is_digest?(cesr_digest_element) when is_atom(cesr_digest_element) do
    Enum.member?(get_all_digests(), cesr_digest_element)
  end

  @type signature() ::
          Cesr.Primitive.CD_0B_Ed25519_signature.t()
          | Cesr.Primitive.CD_0C_ECDSA_secp256k1_signature.t()
          | Cesr.Primitive.CD_0I_ECDSA_secp256r1_signature.t()
          | Cesr.Primitive.CD_1AAE_Ed448_Sig.t()

  @doc """
    All primitives that can be used as a signature (sig)
  """
  def get_all_signatures,
    do: [
      Cesr.Primitive.CD_0B_Ed25519_signature,
      Cesr.Primitive.CD_0C_ECDSA_secp256k1_signature,
      Cesr.Primitive.CD_0I_ECDSA_secp256r1_signature,
      Cesr.Primitive.CD_1AAE_Ed448_Sig
    ]

  def is_signature?(%mod_name{} = cesr_signature_element) 
    when is_struct(cesr_signature_element) 
  do
    Enum.member?(get_all_signatures(), mod_name)
  end

  @type prefix() ::
          Cesr.Primitive.CD_B_Ed25519N.t()
          | Cesr.Primitive.CD_D_Ed25519.t()
          | Cesr.Primitive.CD_E_Blake3_256.t()
          | Cesr.Primitive.CD_F_Blake2b_256.t()
          | Cesr.Primitive.CD_G_Blake2s_256.t()
          | Cesr.Primitive.CD_H_SHA3_256.t()
          | Cesr.Primitive.CD_I_SHA2_256.t()
          | Cesr.Primitive.CD_0D_Blake3_512_Digest.t()
          | Cesr.Primitive.CD_0E_Blake2b_512_Digest.t()
          | Cesr.Primitive.CD_0F_SHA3_512_Digest.t()
          | Cesr.Primitive.CD_0G_SHA2_512_Digest.t()
          | Cesr.Primitive.CD_1AAA_ECDSA_256k1N.t()
          | Cesr.Primitive.CD_1AAB_ECDSA_256k1.t()
          | Cesr.Primitive.CD_1AAC_Ed448N.t()
          | Cesr.Primitive.CD_1AAD_Ed448.t()
          | Cesr.Primitive.CD_1AAI_ECDSA_256r1N.t()
          | Cesr.Primitive.CD_1AAJ_ECDSA_256r1.t()
          | Cesr.Primitive.DummySaidDigest.t()

  @doc """
    All primitives that can derive a prefix (pre)
  """
  def get_all_prefix_derivations,
    do: [
      Cesr.Primitive.CD_B_Ed25519N,
      Cesr.Primitive.CD_D_Ed25519,
      Cesr.Primitive.CD_E_Blake3_256,
      Cesr.Primitive.CD_F_Blake2b_256,
      Cesr.Primitive.CD_G_Blake2s_256,
      Cesr.Primitive.CD_H_SHA3_256,
      Cesr.Primitive.CD_I_SHA2_256,
      Cesr.Primitive.CD_0D_Blake3_512_Digest,
      Cesr.Primitive.CD_0E_Blake2b_512_Digest,
      Cesr.Primitive.CD_0F_SHA3_512_Digest,
      Cesr.Primitive.CD_0G_SHA2_512_Digest,
      Cesr.Primitive.CD_1AAA_ECDSA_256k1N,
      Cesr.Primitive.CD_1AAB_ECDSA_256k1,
      Cesr.Primitive.CD_1AAC_Ed448N,
      Cesr.Primitive.CD_1AAD_Ed448,
      Cesr.Primitive.CD_1AAI_ECDSA_256r1N,
      Cesr.Primitive.CD_1AAJ_ECDSA_256r1
    ]

  def is_prefix_derivation?(%mod_name{} = cesr_digest_or_key_element)
    when is_struct(cesr_digest_or_key_element) 
  do
    Enum.member?(get_all_prefix_derivations(), mod_name)
  end
  def is_prefix_derivation?(cesr_digest_or_key_element)
      when is_atom(cesr_digest_or_key_element) do
    Enum.member?(get_all_prefix_derivations(), cesr_digest_or_key_element)
  end

  @type public_key() ::
          Cesr.Primitive.CD_B_Ed25519N.t()
          | Cesr.Primitive.CD_D_Ed25519.t()
          | Cesr.Primitive.CD_1AAA_ECDSA_256k1N.t()
          | Cesr.Primitive.CD_1AAB_ECDSA_256k1.t()
          | Cesr.Primitive.CD_1AAC_Ed448N.t()
          | Cesr.Primitive.CD_1AAD_Ed448.t()
          | Cesr.Primitive.CD_1AAI_ECDSA_256r1N.t()
          | Cesr.Primitive.CD_1AAJ_ECDSA_256r1.t()

  @type public_key_atom() ::
          Cesr.Primitive.CD_B_Ed25519N
          | Cesr.Primitive.CD_D_Ed25519
          | Cesr.Primitive.CD_1AAA_ECDSA_256k1N
          | Cesr.Primitive.CD_1AAB_ECDSA_256k1
          | Cesr.Primitive.CD_1AAC_Ed448N
          | Cesr.Primitive.CD_1AAD_Ed448
          | Cesr.Primitive.CD_1AAI_ECDSA_256r1N
          | Cesr.Primitive.CD_1AAJ_ECDSA_256r1

  @doc """
    All CESR primitives that reference public keys 
  """
  def get_all_public_keys, do: [
      Cesr.Primitive.CD_B_Ed25519N,
      Cesr.Primitive.CD_D_Ed25519,
      Cesr.Primitive.CD_1AAA_ECDSA_256k1N,
      Cesr.Primitive.CD_1AAB_ECDSA_256k1,
      Cesr.Primitive.CD_1AAC_Ed448N,
      Cesr.Primitive.CD_1AAD_Ed448,
      Cesr.Primitive.CD_1AAI_ECDSA_256r1N,
      Cesr.Primitive.CD_1AAJ_ECDSA_256r1 ]

  def is_public_key?(cesr_public_key_type) when is_atom(cesr_public_key_type) do
    Enum.member?(get_all_public_keys(), cesr_public_key_type)
  end

  @type sequence() :: Cesr.Primitive.CD_A_Ed25519_Seed.t()

  @doc """
    All primitives that can hold a sequence number (snu).

    See: Illuminatus trilogy for words that make one's psych uncomfortable
  """
  def get_all_sequence_numbers,
    do: [
      Cesr.Primitive.CD_0A_Random_salt_seed_nonce
    ]

  def is_sequence_number?(%mod_name{}) do
    Enum.member?(get_all_sequence_numbers(), mod_name)
  end

  @type first_seen() :: Cesr.Primitive.CD_0A_Random_salt_seed_nonce.t()

  @doc """
    All primitives that can hold a first seen number (fnu). See: Illuminatus trilogy for words that make one's psych uncomfortable
  """
  def get_all_first_seen_numbers,
    do: [
      Cesr.Primitive.CD_0A_Random_salt_seed_nonce
    ]

  def is_first_seen_number?(cesr_sequence_number) do
    %mod_name{} = cesr_sequence_number
    Enum.member?(get_all_first_seen_numbers(), mod_name)
  end

  @type cesr_date() :: Cesr.Primitive.CD_1AAG_DateTime.t()

  @doc """
    All primitives that can hold a date (dts).
  """
  def get_all_date_primitives,
    do: [Cesr.Primitive.CD_1AAG_DateTime]

  def is_date_primitive?(cesr_sequence_number) do
    %mod_name{} = cesr_sequence_number
    Enum.member?(get_all_date_primitives(), mod_name)
  end

  @type sad_path_type() :: Cesr.Primitive.CesrStringB64.t()

  def get_all_sad_path_primitives(), do: [Cesr.Primitive.CesrStringB64]

  def is_sad_path_primitive?(%mod_name{}) do 
    Enum.member?(get_all_sad_path_primitives(), mod_name)
  end

  def all_count_codes_v1() do
    Enum.map(
      Cesr.CountCode.Generator.CntCodeV1Generator.primitiveTypeDescriptions() ++
        Cesr.CountCode.Generator.CntCodeV1Generator.quadletTypeDescriptions(),
      fn x -> Module.concat(Cesr.CountCodeKERIv1, "CD_#{elem(x, 0)}_#{elem(x, 2)}") end
    )
  end

  def all_count_codes_v2() do
    Enum.map(
      Cesr.CountCode.Generator.CntCodeV2Generator.typeDescriptions(),
      fn x -> Module.concat(Cesr.CountCodeKERIv2, "CD_#{elem(x, 0)}_#{elem(x, 2)}") end
    )
  end

  def all_primitives() do
    vanilla_primitives =
      Enum.map(
        Cesr.Primitive.Generator.OneCharFixedPrimitive.typeDescriptions() ++
          Cesr.Primitive.Generator.TwoCharFixedPrimitive.typeDescriptions() ++
          Cesr.Primitive.Generator.FourCharFixedPrimitive.typeDescriptions() ++
          Cesr.Primitive.Generator.OneCharacterLabelPrimitives.typeDescriptions(),
        fn x -> Module.concat(Cesr.Primitive, "CD_#{elem(x, 0)}_#{elem(x, 1)}") end
      )

    variable_length_primitives =
      Enum.map(
        Cesr.Primitive.Generator.VariableLengthPrimitive.typeDescriptions(),
        fn x -> Module.concat(Cesr.Primitive, "#{elem(x, 1)}") end
      )

    index_primitives =
      Enum.map(
        Cesr.Index.OneCharIndexedPrimitiveGenerator.typeDescriptions() ++
          Cesr.Index.TwoCharIndexedPrimitiveGenerator.typeDescriptions(),
        # different element in index generators
        fn x ->
          Module.concat(Cesr.Primitive.Indexes, "IDX_#{elem(x, 0)}_#{elem(x, 2)}")
        end
      )

    vanilla_primitives ++ variable_length_primitives ++ index_primitives
  end

  @doc """
    Takes a count code struct and evaluates whether it counts children or quadlets/triplets.
    
    Only in CESR v1 and only from the list that counts cesr elements, all other
    count codes count quads/triplets.
  """
  def counts_children?(count_code_struct) do
    count_code_struct in Enum.map(
      Cesr.CountCode.Generator.CntCodeV1Generator.primitiveTypeDescriptions(),
      fn x -> Module.concat(Cesr.CountCodeKERIv1, "CD_#{elem(x, 0)}_#{elem(x, 2)}") end
    )
  end

  def is_count_code_v1?(x), do: x in all_count_codes_v1()
  def is_count_code_v2?(x), do: x in all_count_codes_v2()
  def is_count_code?(x), do: is_count_code_v1?(x) or is_count_code_v2?(x)
  def is_primitive?(x), do: x in all_primitives()
end
