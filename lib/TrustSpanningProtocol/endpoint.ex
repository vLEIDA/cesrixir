defmodule TSP.Endpoint do
  alias Cesr.CountCodeKERIv2.CD_A_GenericGroup
  alias Cesr.CountCodeKERIv2.CD_dashE_BigESSRWrapperGroup
  alias Cesr.CountCodeKERIv2.CD_dashJ_BigGenericListGroup
  alias Cesr.CountCodeKERIv2.CD_dashZ_BigESSRPayloadGroup
  alias Cesr.Primitive.CesrBytes
  alias TSP.Endpoint
  alias TSP.Keystore
  alias TSP.Message
  alias TSP.Relationship

  use GenServer
  @enforce_keys [:relationships]
  defstruct     [:relationships]

  @impl true
  def init(:empty) do
    {:ok, %Endpoint{relationships: []}}
  end

  @impl true
  def handle_call({:add_vid, our_vid}, _from, %Endpoint{} = state) do
    case Enum.any?(state.relationships, fn r -> r.our_vid == our_vid end) do
      true  -> {:reply, :error_vid_already_exists, state} # could also be a no-op
      false -> {:reply, :ok, %{state | :relationships => state.relationships ++ [Relationship.new(our_vid)]}}
    end
  end

  def handle_call({:oobi, our_vid, their_vid, their_pid}, _from, %Endpoint{} = state) do
    case Enum.find(state.relationships, fn r -> r.our_vid == our_vid end) do
      :nil -> {:reply, :error_vid_not_created_yet, state}
      old_relationship -> {:ok, their_keystore} = GenServer.call(their_pid, {:public_keys, their_vid})
                          new_relationship = %{old_relationship | their_vid: their_vid, their_pid: their_pid, their_keystore: their_keystore}
                          other_relationships = Enum.filter(state.relationships, fn r -> r.our_vid != our_vid end)
                          {:reply, :ok, %{state | :relationships => other_relationships ++ [new_relationship]}}
    end
  end

  def handle_call({:public_keys, our_vid}, _from, %Endpoint{} = state) do
    case Enum.find(state.relationships, fn r -> r.our_vid == our_vid end) do
      :nil -> {:reply, :error_keystore_not_found, state}
      old_relationship -> public_keystore = %{Keystore.new() | crypto_public_key: old_relationship.our_keystore.crypto_public_key,
                                                               sig_public_key:    old_relationship.our_keystore.sig_public_key}
                          {:reply, {:ok, public_keystore}, state}
    end
  end

  def handle_call({:create_message, our_vid, their_vid, route, payload}, _from, %Endpoint{} = state) do
    case Enum.find(state.relationships, fn r -> r.our_vid == our_vid end) do
      :nil -> {:reply, :error_keystore_not_found, state}
      old_relationship -> message = Message.new(our_vid, their_vid, route, payload,
                            old_relationship.their_keystore.crypto_public_key,
                            old_relationship.our_keystore.sig_secret_key)
                          {:reply, {:ok, message}, state}
    end
  end

  # routed message: verify it, unseal it, reseal for next recipient, sign and pass it on
  def handle_call({:route_message, %Message{
    envelope:  %CD_dashE_BigESSRWrapperGroup{cesr_elements:
      [_tsp_version, %CesrBytes{code: _code_1, payload: vid_sender},
        %CesrBytes{code: _code_2, payload: vid_receiver}]},
    payload:   %CD_dashZ_BigESSRPayloadGroup{cesr_elements:
      [_payload_tag, %CesrBytes{code: _code_3, payload: vid_sender_payload},
        %CD_dashJ_BigGenericListGroup{cesr_elements: [
          %CesrBytes{code: _code_4, payload: first_hop},
          %CesrBytes{code: _code_5, payload: next_hop} | rest_of_hops]}, _payload_group]},
    signature: _signature} = message}, _from, %Endpoint{} = state) do
        with :ok <- (if vid_sender == vid_sender_payload, do: :ok, else: :error_vid_mismatch),
             :ok <- (if vid_receiver == first_hop, do: :ok, else: :error_wrong_recipient),
             %Relationship{} = incoming_relationship <- Enum.find(state.relationships,
                                               fn r -> r.our_vid == vid_receiver end),
             %Relationship{} = outgoing_relationship <- Enum.find(state.relationships,
                                               fn r -> r.their_vid == next_hop end),
             :ok <- (if :true == Message.verify_signature(message, incoming_relationship.their_keystore.sig_public_key),
                                 do: :ok, else: :error_sig_not_verified),
             unsealed_payload <- Message.unseal_payload(message, incoming_relationship.our_keystore.crypto_public_key,
                                 incoming_relationship.our_keystore.crypto_secret_key),
             next_hops_string_list <- [next_hop | Enum.map(rest_of_hops, fn %CesrBytes{code: _code, payload: payload} -> payload end)],
             %Message{} = outgoing_message <- Message.new(outgoing_relationship.our_vid,
                          next_hop, next_hops_string_list, unsealed_payload,
                          outgoing_relationship.their_keystore.crypto_public_key,
                          outgoing_relationship.our_keystore.sig_secret_key) do
          {:reply, {:next_route, outgoing_relationship.their_pid, outgoing_message}, state}
        else
          :nil  -> {:reply, :error_relationship_not_found, state}
          error -> {:reply, error, state}
        end
  end
  # terminating condition: one entry in hop list
  def handle_call({:route_message, %Message{
    envelope:  %CD_dashE_BigESSRWrapperGroup{cesr_elements:
      [_tsp_version, %CesrBytes{code: _code_1, payload: vid_sender},
        %CesrBytes{code: _code_2, payload: vid_receiver}]},
    payload:   %CD_dashZ_BigESSRPayloadGroup{cesr_elements:
      [_payload_tag, %CesrBytes{code: _code_3, payload: vid_sender_payload},
        %CD_dashJ_BigGenericListGroup{cesr_elements: [
          %CesrBytes{code: _code_4, payload: final_vid}]}, _payload_group]},
    signature: _signature} = message}, _from, %Endpoint{} = state) do
        with :ok <- (if vid_sender == vid_sender_payload, do: :ok, else: :error_vid_mismatch),
             :ok <- (if vid_receiver == final_vid, do: :ok, else: :error_wrong_recipient),
             %Relationship{} = relationship <- Enum.find(state.relationships,
                                               fn r -> r.our_vid == vid_receiver end),
             :ok <- (if :true == Message.verify_signature(message, relationship.their_keystore.sig_public_key),
                                 do: :ok, else: :error_sig_not_verified),
             unsealed_payload <- Message.unseal_payload(message, relationship.our_keystore.crypto_public_key,
                                 relationship.our_keystore.crypto_secret_key) do

          {:reply, {:route_done, unsealed_payload}, state}
        else
          :nil  -> {:reply, :error_relationship_not_found, state}
          error -> {:reply, error, state}
        end
  end
  # invalid case: tried to route a message with an empty hop list
  def handle_call({:route_message, %Message{
    envelope:  _envelope,
    payload:   %CD_dashZ_BigESSRPayloadGroup{cesr_elements:
      [_payload_tag, _vid_sender_payload, %CD_dashJ_BigGenericListGroup{cesr_elements: []},
      %CD_A_GenericGroup{cesr_elements: [_payload_primitive]}]},
    signature: _signature}}, _from, %Endpoint{} = state) do
      {:reply, :error_empty_hop_list, state}
  end

  def handle_call({:unseal_payload, our_vid, message}, _from, %Endpoint{} = state) do
    case Enum.find(state.relationships, fn r -> r.our_vid == our_vid end) do
      :nil -> {:reply, :error_keystore_not_found, state}
      old_relationship -> payload = Message.unseal_payload(message,
                            old_relationship.our_keystore.crypto_public_key,
                            old_relationship.our_keystore.crypto_secret_key)
                          {:reply, payload, state}
    end
  end

  def handle_call({:verify_signature, vid_sender, message}, _from, %Endpoint{} = state) do
    # verify from either endpoint for convenience (the sig key is public knowledge)
    reply = case Enum.find(state.relationships, fn r -> r.our_vid == vid_sender end) do
      :nil -> case Enum.find(state.relationships, fn r -> r.their_vid == vid_sender end) do
        :nil -> :error_keystore_not_found
        relationship -> Message.verify_signature(message, relationship.their_keystore.sig_public_key)
      end
      relationship -> Message.verify_signature(message, relationship.our_keystore.sig_public_key)
    end
    {:reply, reply, state}
  end

  # everything below this is just to verify that endpoints control keys
  # (https://trustoverip.github.io/tswg-tsp-specification/#verification)

  def handle_call({:verify_crypto_key, our_vid, encrypted_payload}, _from, %Endpoint{} = state) do
    case Enum.find(state.relationships, fn r -> r.our_vid == our_vid end) do
      :nil -> {:reply, :error_crypto_key_not_found, state}
      relationship -> decrypted_payload = :libsodium_crypto_box.seal_open(encrypted_payload,
                        relationship.our_keystore.crypto_public_key,
                        relationship.our_keystore.crypto_secret_key)
                      {:reply, {:ok, decrypted_payload}, state}
    end
  end

  def handle_call({:verify_sig_key, our_vid, payload}, _from, %Endpoint{} = state) do
    case Enum.find(state.relationships, fn r -> r.our_vid == our_vid end) do
      :nil -> {:reply, :error_public_key_not_found, state}
      relationship -> encrypted_payload = :libsodium_crypto_sign_ed25519.crypto_sign_ed25519(
                        payload, relationship.our_keystore.sig_secret_key)
                      {:reply, {:ok, encrypted_payload}, state}
    end
  end

  def verify_keys(their_vid, their_pid) do
    with {:ok, their_keystore} <- GenServer.call(their_pid, {:public_keys, their_vid}),
      payload <- :base64.encode(:crypto.strong_rand_bytes(8)),
      encrypted_payload <- :libsodium_crypto_box.seal(payload, their_keystore.crypto_public_key),
      {:ok, decrypted_payload} <- GenServer.call(their_pid, {:verify_crypto_key, their_vid, encrypted_payload}),
      crypto_verified <- payload == decrypted_payload,
      {:ok, signed_payload} <- GenServer.call(their_pid, {:verify_sig_key, their_vid, payload}),
      sig_verified <- payload == :libsodium_crypto_sign_ed25519.open(signed_payload, their_keystore.sig_public_key)
    do
      if crypto_verified and sig_verified, do: :ok, else: :error_verification_failed
    end
  end
end
