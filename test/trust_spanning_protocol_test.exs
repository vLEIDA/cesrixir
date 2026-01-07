defmodule TrustSpanningProtocolTest do
  alias Cesr.CesrElement
  alias Cesr.CountCodeKERIv2.CD_A_GenericGroup
  alias Cesr.CountCodeKERIv2.CD_dashC_BigAttachmentGroup
  alias Cesr.CountCodeKERIv2.CD_dashE_BigESSRWrapperGroup
  alias Cesr.CountCodeKERIv2.CD_dashJ_BigGenericListGroup
  alias Cesr.CountCodeKERIv2.CD_dashK_BigControllerIdxSigs
  alias Cesr.CountCodeKERIv2.CD_dashZ_BigESSRPayloadGroup
  alias Cesr.Primitive.CD_0B_Ed25519_signature
  alias Cesr.Primitive.CD_X_Tag3
  alias Cesr.Primitive.CD_Y_Tag7
  alias Cesr.Primitive.CesrBytes
  alias TSP.Endpoint
  alias TSP.Keystore
  alias TSP.Message
  alias TSP.Relationship

  use ExUnit.Case, async: true

  # OOBI == out of band introduction
  test "OOBI 2 Endpoints" do
    # create endpoints and vids (each vid automatically creates a random keystore)
    {:ok, endpoint_1} = GenServer.start_link(Endpoint, :empty, [])
    {:ok, endpoint_2} = GenServer.start_link(Endpoint, :empty, [])
    vid_1 = "AAAAAAAAAA"
    vid_2 = "BBBBBBBBBB"
    :ok = GenServer.call(endpoint_1, {:add_vid, vid_1})
    :ok = GenServer.call(endpoint_2, {:add_vid, vid_2})

    # we don't normally grab the keystores like this but we want to verify them
    keystore_1 = Enum.at(:sys.get_state(endpoint_1).relationships, 0).our_keystore
    keystore_1_public = %{keystore_1 | sig_secret_key: :nil, crypto_secret_key: :nil}
    keystore_2 = Enum.at(:sys.get_state(endpoint_2).relationships, 0).our_keystore
    keystore_2_public = %{keystore_2 | sig_secret_key: :nil, crypto_secret_key: :nil}
    assert :sys.get_state(endpoint_1).relationships == [%Relationship{
      our_vid: vid_1,
      their_vid: :nil,
      our_keystore: keystore_1,
      their_keystore: Keystore.new(),
      their_pid: :nil
    }]
    assert :sys.get_state(endpoint_2).relationships == [%Relationship{
      our_vid: vid_2,
      their_vid: :nil,
      our_keystore: keystore_2,
      their_keystore: Keystore.new(),
      their_pid: :nil
    }]

    # oobi endpoints and check public keys were retrieved
    :ok = GenServer.call(endpoint_1, {:oobi, vid_1, vid_2, endpoint_2})
    assert :sys.get_state(endpoint_1).relationships == [%Relationship{
      our_vid: vid_1,
      their_vid: vid_2,
      our_keystore: keystore_1,
      their_keystore: keystore_2_public,
      their_pid: endpoint_2
    }]
    :ok = GenServer.call(endpoint_2, {:oobi, vid_2, vid_1, endpoint_1})
    assert :sys.get_state(endpoint_2).relationships == [%Relationship{
      our_vid: vid_2,
      their_vid: vid_1,
      our_keystore: keystore_2,
      their_keystore: keystore_1_public,
      their_pid: endpoint_1
    }]

    # cryptographically verify that they also have the private keys
    # (https://trustoverip.github.io/tswg-tsp-specification/#verification)
    assert :ok == Endpoint.verify_keys(vid_1, endpoint_1)
    assert :ok == Endpoint.verify_keys(vid_2, endpoint_2)
  end

  test "Message" do
    # create endpoints and vids, oobi endpoints
    vid_1 = "AAAAAAAAAA"
    vid_2 = "BBBBBBBBBB"
    payload = "12345"
    {:ok, endpoint_1} = GenServer.start_link(Endpoint, :empty, [])
    {:ok, endpoint_2} = GenServer.start_link(Endpoint, :empty, [])
    :ok = GenServer.call(endpoint_1, {:add_vid, vid_1})
    :ok = GenServer.call(endpoint_2, {:add_vid, vid_2})
    :ok = GenServer.call(endpoint_1, {:oobi, vid_1, vid_2, endpoint_2})
    :ok = GenServer.call(endpoint_2, {:oobi, vid_2, vid_1, endpoint_1})
    {:ok, message} = GenServer.call(endpoint_1, {:create_message, vid_1, vid_2, [], payload})

    # verify envelope struct
    %CD_dashE_BigESSRWrapperGroup{
      cesr_elements: [
        %CD_Y_Tag7{
          code: "Y",
          payload: <<77, 35, 254, 0, 0, 1::size(2)>> # see test "Tag"
        },
        %CesrBytes{code: :auto, payload: ^vid_1},
        %CesrBytes{code: :auto, payload: ^vid_2}
      ]
    } = message.envelope

    # verify payload struct
    %CD_dashZ_BigESSRPayloadGroup{
      cesr_elements: [
        %CD_X_Tag3{
          code: "X",
          payload: <<72, 36, 2::size(2)>>
        },
        %CesrBytes{code: :auto, payload: ^vid_1},
        %CD_dashJ_BigGenericListGroup{cesr_elements: []},
        %CD_A_GenericGroup{
          cesr_elements: [
            %CesrBytes{
              code: :auto,
              payload: _encrypted_payload
            }
          ]
        }
      ]
    } = message.payload

    # verify signature struct
    %CD_dashC_BigAttachmentGroup{
      cesr_elements: [
        %CD_dashK_BigControllerIdxSigs{
          cesr_elements: [
            %CD_0B_Ed25519_signature{
              code: "0B",
              payload: _signature
            }
          ]
        }
      ]
    } = message.signature

    # unseal payload
    assert payload == GenServer.call(endpoint_2, {:unseal_payload, vid_2, message})

    # verify signature (either endpoint can verify with the sender's public sig key)
    assert :true == GenServer.call(endpoint_1, {:verify_signature, vid_1, message})
    assert :true == GenServer.call(endpoint_2, {:verify_signature, vid_1, message})
  end

  test "Nested Message" do
    # Payload Nesting (https://trustoverip.github.io/tswg-tsp-specification/#payload-nesting)
    # Endpoints A & B have a prior relationship (vid_a0, vid_b0). They can embed a new
    # relationship (vid_a1, vid_b1) in the encrypted payload of (vid_a0, vid_b0) messages.
    #
    # Outer_Message  = {Envelope_0, Payload_0, Signature_0},
    # Inner_Message  = {Envelope_1, Payload_1, Signature_1},
    # Nested_Message = {Envelope_0, Control_Fields_0, TSP_SEAL_0(Inner_Message), Signature0}

    # create endpoints and vids, oobi endpoints
    {:ok, endpoint_A} = GenServer.start_link(Endpoint, :empty, [])
    {:ok, endpoint_B} = GenServer.start_link(Endpoint, :empty, [])
    [vid_a0, vid_a1, vid_b0, vid_b1] = ["a0", "a1", "b0", "b1"]
    :ok = GenServer.call(endpoint_A, {:add_vid, vid_a0})
    :ok = GenServer.call(endpoint_A, {:add_vid, vid_a1})
    :ok = GenServer.call(endpoint_B, {:add_vid, vid_b0})
    :ok = GenServer.call(endpoint_B, {:add_vid, vid_b1})
    :ok = GenServer.call(endpoint_A, {:oobi, vid_a0, vid_b0, endpoint_B})
    :ok = GenServer.call(endpoint_A, {:oobi, vid_a1, vid_b1, endpoint_B})
    :ok = GenServer.call(endpoint_B, {:oobi, vid_b0, vid_a0, endpoint_A})
    :ok = GenServer.call(endpoint_B, {:oobi, vid_b1, vid_a1, endpoint_A})

    # sender (A) creates inner message
    payload = "12345"
    {:ok, inner_message} = GenServer.call(endpoint_A, {:create_message, vid_a0, vid_b0, [], payload})
    inner_message_bytes = Message.to_b64(inner_message)

    # sender (A) creates outer message
    {:ok, outer_message} = GenServer.call(endpoint_A, {:create_message, vid_a1, vid_b1, [], inner_message_bytes})

    # verify outer signature (either endpoint can verify with the sender's public sig key)
    assert :true == GenServer.call(endpoint_A, {:verify_signature, vid_a1, outer_message})
    assert :true == GenServer.call(endpoint_B, {:verify_signature, vid_a1, outer_message})

    # receiving endpoint (B) unseals the inner message
    unsealed_bytes = GenServer.call(endpoint_B, {:unseal_payload, vid_b1, outer_message})
    assert unsealed_bytes == inner_message_bytes
    unsealed_message = Message.from_b64(unsealed_bytes)

    # verify inner signature
    assert :true == GenServer.call(endpoint_A, {:verify_signature, vid_a0, unsealed_message})
    assert :true == GenServer.call(endpoint_B, {:verify_signature, vid_a0, unsealed_message})

    # verify inner payload
    assert payload == GenServer.call(endpoint_B, {:unseal_payload, vid_b0, unsealed_message})
  end

  test "Routed Messages" do
    # Direct Neighbor Relationship and Routing (https://trustoverip.github.io/tswg-tsp-specification/#direct-neighbor-relationship-and-routing)
    # +-+ p0  q0 +-+    A & B are endpoints. They want to hide the fact they're communicating.
    # |P| <----> |Q|    P is A's intermediary and Q is B's intermediary.
    # +-+        +-+    A & P communicate with vids a1 and p1.
    #  ^ p1       ^ q1  P & Q communicate with vids p0 and q0.
    #  |          |     Q & B communicate with vids q1 and b1.
    #  v a1       v b1  A & B don't communicate directly. Assuming that P & Q are high-traffic
    # +-+        +-+    nodes, an attacker can't prove that A & B have communicated.
    # |A|        |B|
    # +-+        +-+

    # set up endpoints, intermediaries, and vids
    {:ok, endpoint_A}     = GenServer.start_link(Endpoint, :empty, [])
    {:ok, intermediary_P} = GenServer.start_link(Endpoint, :empty, [])
    {:ok, intermediary_Q} = GenServer.start_link(Endpoint, :empty, [])
    {:ok, endpoint_B}     = GenServer.start_link(Endpoint, :empty, [])
    [vid_a1, vid_p1, vid_p0, vid_q0, vid_q1, vid_b1] = ["a1", "p1", "p0", "q0", "q1", "b1"]
    :ok = GenServer.call(endpoint_A,     {:add_vid, vid_a1})
    :ok = GenServer.call(intermediary_P, {:add_vid, vid_p1})
    :ok = GenServer.call(intermediary_P, {:add_vid, vid_p0})
    :ok = GenServer.call(intermediary_Q, {:add_vid, vid_q0})
    :ok = GenServer.call(intermediary_Q, {:add_vid, vid_q1})
    :ok = GenServer.call(endpoint_B,     {:add_vid, vid_b1})
    :ok = GenServer.call(endpoint_A,     {:oobi, vid_a1, vid_p1, intermediary_P}) # A <-> P
    :ok = GenServer.call(intermediary_P, {:oobi, vid_p1, vid_a1, endpoint_A})     # A <-> P
    :ok = GenServer.call(intermediary_P, {:oobi, vid_p0, vid_q0, intermediary_Q}) # P <-> Q
    :ok = GenServer.call(intermediary_Q, {:oobi, vid_q0, vid_p0, intermediary_P}) # P <-> Q
    :ok = GenServer.call(intermediary_Q, {:oobi, vid_q1, vid_b1, endpoint_B})     # Q <-> B
    :ok = GenServer.call(endpoint_B,     {:oobi, vid_b1, vid_q1, intermediary_Q}) # Q <-> B
    payload = "12345"

    # try some shorter routes first
    {:ok, empty_hop_list}     = GenServer.call(endpoint_A,     {:create_message, vid_a1, vid_p1, [], payload})
    :error_empty_hop_list     = GenServer.call(intermediary_P, {:route_message,  empty_hop_list})

    {:ok, wrong_recipient}    = GenServer.call(endpoint_A,     {:create_message, vid_a1, vid_p1, [vid_q1], payload})
    :error_wrong_recipient    = GenServer.call(intermediary_P, {:route_message,  wrong_recipient})

    {:ok, single_hop_message} = GenServer.call(endpoint_A,     {:create_message, vid_a1, vid_p1, [vid_p1], payload})
    {:route_done, ^payload}   = GenServer.call(intermediary_P, {:route_message,  single_hop_message})

    # and now the full route from A -> P -> Q -> B
    {:ok, message_A_to_P}                          = GenServer.call(endpoint_A,     {:create_message, vid_a1, vid_p1,
                                                     [vid_p1, vid_q0, vid_b1], payload})
    {:next_route, ^intermediary_Q, message_P_to_Q} = GenServer.call(intermediary_P, {:route_message,  message_A_to_P})
    {:next_route, ^endpoint_B, message_Q_to_B}     = GenServer.call(intermediary_Q, {:route_message,  message_P_to_Q})
    {:route_done, ^payload}                        = GenServer.call(endpoint_B,     {:route_message,  message_Q_to_B})
  end

  test "Endpoint-to-Endpoint Message" do
    # 5.4 Endpoint-to-Endpoint Messages
    # https://trustoverip.github.io/tswg-tsp-specification/#endpoint-to-endpoint-messages

    # set up endpoints, intermediaries, and vids
    {:ok, endpoint_A}     = GenServer.start_link(Endpoint, :empty, [])
    {:ok, intermediary_P} = GenServer.start_link(Endpoint, :empty, [])
    {:ok, intermediary_Q} = GenServer.start_link(Endpoint, :empty, [])
    {:ok, endpoint_B}     = GenServer.start_link(Endpoint, :empty, [])
    [vid_a1, vid_a2, vid_p1, vid_p0, vid_q0, vid_q1, vid_b1, vid_b2] =
      ["a1",   "a2",   "p1",   "p0",   "q0",   "q1",   "b1",   "b2"]
    :ok = GenServer.call(endpoint_A,     {:add_vid, vid_a1})
    :ok = GenServer.call(endpoint_A,     {:add_vid, vid_a2})
    :ok = GenServer.call(intermediary_P, {:add_vid, vid_p1})
    :ok = GenServer.call(intermediary_P, {:add_vid, vid_p0})
    :ok = GenServer.call(intermediary_Q, {:add_vid, vid_q0})
    :ok = GenServer.call(intermediary_Q, {:add_vid, vid_q1})
    :ok = GenServer.call(endpoint_B,     {:add_vid, vid_b1})
    :ok = GenServer.call(endpoint_B,     {:add_vid, vid_b2})
    :ok = GenServer.call(endpoint_A,     {:oobi, vid_a1, vid_p1, intermediary_P}) # A <-> P
    :ok = GenServer.call(intermediary_P, {:oobi, vid_p1, vid_a1, endpoint_A})     # A <-> P
    :ok = GenServer.call(intermediary_P, {:oobi, vid_p0, vid_q0, intermediary_Q}) # P <-> Q
    :ok = GenServer.call(intermediary_Q, {:oobi, vid_q0, vid_p0, intermediary_P}) # P <-> Q
    :ok = GenServer.call(intermediary_Q, {:oobi, vid_q1, vid_b1, endpoint_B})     # Q <-> B
    :ok = GenServer.call(endpoint_B,     {:oobi, vid_b1, vid_q1, intermediary_Q}) # Q <-> B
    :ok = GenServer.call(endpoint_A,     {:oobi, vid_a2, vid_b2, endpoint_B})     # A <-> B
    :ok = GenServer.call(endpoint_B,     {:oobi, vid_b2, vid_a2, endpoint_A})     # A <-> B
    payload = "12345"

    # Create the inner message first and convert to bytes
    {:ok, a_end_to_end_b} = GenServer.call(endpoint_A, {:create_message, vid_a2, vid_b2, [], payload})
    a_end_to_end_b_bytes  = Message.to_b64(a_end_to_end_b)

    # Route the inner message from A -> P -> Q -> B
    {:ok, message_A_to_P}                          = GenServer.call(endpoint_A,     {:create_message, vid_a1, vid_p1,
                                                     [vid_p1, vid_q0, vid_b1], a_end_to_end_b_bytes})
    {:next_route, ^intermediary_Q, message_P_to_Q} = GenServer.call(intermediary_P, {:route_message,  message_A_to_P})
    {:next_route, ^endpoint_B, message_Q_to_B}     = GenServer.call(intermediary_Q, {:route_message,  message_P_to_Q})
    {:route_done, ^a_end_to_end_b_bytes}           = GenServer.call(endpoint_B,     {:route_message,  message_Q_to_B})

    # Unseal and verify the inner message
    unsealed_message = Message.from_b64(a_end_to_end_b_bytes)

    # Verify inner signature
    assert :true == GenServer.call(endpoint_A, {:verify_signature, vid_a2, unsealed_message})
    assert :true == GenServer.call(endpoint_B, {:verify_signature, vid_a2, unsealed_message})

    # Verify inner payload
    assert payload == GenServer.call(endpoint_B, {:unseal_payload, vid_b2, unsealed_message})
  end

  test "Tag" do
    {{:ok, tag}, ""} = CD_Y_Tag7.from_b64("YTSP-AAB")
    assert tag == %CD_Y_Tag7{
      code: "Y",
      payload: <<77, 35, 254, 0, 0, 1::size(2)>>
    }
    assert CesrElement.to_b64(tag) == "YTSP-AAB"
    # to translate the payload back to base64 manually:
    # 77       35       254      0        0        1::size(2) <- payload in bytes
    # 01001101 00100011 11111110 00000000 00000000 01         <- convert to bits
    # 010011 010010 001111 111110 000000 000000 000001        <- group by 6 (=sizeof(b64))
    # 19     18     15     62     0      0      1             <- convert to decimal
    # T      S      P      -      A      A      B             <- lookup in b64 table
  end

  test "Basic encryption" do
    keystore = Keystore.random()
    payload = "12345"
    encrypted = :libsodium_crypto_box.seal(payload, keystore.crypto_public_key)
    assert payload == :libsodium_crypto_box.seal_open(encrypted,
      keystore.crypto_public_key, keystore.crypto_secret_key)
  end

  test "Basic signing" do
    keystore = Keystore.random()
    payload = "12345"
    signed_msg = :libsodium_crypto_sign_ed25519.crypto_sign_ed25519(payload, keystore.sig_secret_key)
    assert payload == :libsodium_crypto_sign_ed25519.open(signed_msg, keystore.sig_public_key)
  end
end
