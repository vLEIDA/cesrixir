defmodule TSP.Message do
  alias Cesr
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
  alias TSP.Message

  @enforce_keys [:envelope, :payload, :signature]
  defstruct     [:envelope, :payload, :signature]

  # 3. Messages (https://trustoverip.github.io/tswg-tsp-specification/#messages)
  # TSP_Message = {TSP_Envelope, TSP_Payload, TSP_Signature}
  def new(sender, receiver, route, plaintext, receiver_crypto_public_key, sender_sig_secret_key) do
    with {:ok, envelope}  <- make_envelope(sender, receiver),
         {:ok, payload}   <- make_payload(sender, route, plaintext, receiver_crypto_public_key),
         {:ok, signature} <- make_signature(envelope, payload, sender_sig_secret_key) do
      %Message{envelope: envelope, payload: payload, signature: signature}
    end
  end

  defp make_envelope(sender, receiver) do
    # 3.1 TSP Envelope (https://trustoverip.github.io/tswg-tsp-specification/#tsp-envelope)
    # TSP_Envelope = {TSP_Tag, TSP_Version, VID_sndr, VID_rcvr | NULL}
    with {{:ok, tsp_version}, ""} = CD_Y_Tag7.from_b64("YTSP-AAB"),
          {:ok, vid_sender}       = CesrBytes.new(sender),
          {:ok, vid_receiver}     = CesrBytes.new(receiver) do
      # 9.1 TSP Envelope Encoding (https://trustoverip.github.io/tswg-tsp-specification/#tsp-envelope-encoding)
      # tsp_tag:      wrap everything in a BigESSRWrapperGroup (-E) (indicates it's an envelope)
      # tsp_version:  first version is YTSP-AAB (Y indicates a 7-letter tag primitive,
      #               TSP == Trust Spanning Protocol, AAB == 001 in base64 indices)
      # vid_sender:   encode as variable-length primitive (4A/5A/etc depending on padding)
      # vid_receiver: optional, same encoding as receiver (we'll use :nil if it's missing)
      CD_dashE_BigESSRWrapperGroup.new([tsp_version, vid_sender, vid_receiver])
    end
  end

  defp make_cesr_bytes!(string) do
    {:ok, cesr} = CesrBytes.new(string)
    cesr
  end

  defp make_payload(sender, route, plaintext, receiver_crypto_public_key) do
    # 9.2 TSP Payload Encoding (https://trustoverip.github.io/tswg-tsp-specification/#tsp-payload-encoding)
    # The cesr stream looks something like this, "|" meaning "or":
    #   -Z## | -0Z####, XSCS, VID_sndr, Padding_field, -A## | -0A####, higher-layer-interleaved-payload-stream
    # -Z:       wrap everything in a BigESSRPayloadGroup (Encrypt Sender, Sign Receiver)
    # XSCS:     put "SCS" in a 3-letter tag (payload is a Sniffable CESR Stream)
    # VID_sndr: encode as a variable-length primitive (the "encrypt sender" part of ESSR)
    # hop_list: list of vids to route the message to (empty if it's a direct message)
    # padding:  skipping this since our cesr implementation can calculate padding properly
    # -A:       wrap the payload in a GenericGroup
    # higher-layer-interleaved-payload-stream: encrypted payload (or nested TSP message)
    with {{:ok, payload_tag}, ""} <- CD_X_Tag3.from_b64("XSCS"),
          {:ok, vid_sender}       <- CesrBytes.new(sender),
          {:ok, hop_list}         <- CD_dashJ_BigGenericListGroup.new(Enum.map(route, &make_cesr_bytes!/1)),
          # {:ok, padding_field}  <- CesrBytes.new(""),
          encrypted_payload       <- :libsodium_crypto_box.seal(plaintext, receiver_crypto_public_key),
          {:ok, payload_cesr}     <- CesrBytes.new(encrypted_payload) do
      CD_dashZ_BigESSRPayloadGroup.new([payload_tag, vid_sender, hop_list, CD_A_GenericGroup.new([payload_cesr])])
    end
  end

  defp make_signature(envelope, payload, sender_sig_secret_key) do
    # 3.3 TSP Signature (https://trustoverip.github.io/tswg-tsp-specification/#tsp-signature)
    # TSP_Signature = TSP_SIGN({TSP_Envelope, TSP_Payload})
    with text            <- Cesr.produce_text_stream([envelope, payload]),
         signature       <- :libsodium_crypto_sign_ed25519.detached(text, sender_sig_secret_key),
         {:ok, sig_cesr} <- CD_0B_Ed25519_signature.new(signature) do
      # 9.3 TSP Signature Encoding (https://trustoverip.github.io/tswg-tsp-specification/#tsp-signature-encoding)
      # 1. wrap everything in a BigAttachmentGroup (-C) so we know it's signatures
      # 2. inside that, wrap signatures & indexes in a BigControllerIdxSigs (-K)
      # 3. signature types match the keys, we used ed25519 so Ed25519_signature (0B)
      CD_dashC_BigAttachmentGroup.new([CD_dashK_BigControllerIdxSigs.new([sig_cesr])])
    end
  end

  def unseal_payload(%Message{envelope: _envelope,
      payload: %CD_dashZ_BigESSRPayloadGroup{cesr_elements:
        [_payload_tag, _vid_sender, _hop_list, %CD_A_GenericGroup{cesr_elements: [payload_primitive]}]},
      signature: _signature}, receiver_crypto_public_key, receiver_crypto_secret_key) do
    :libsodium_crypto_box.seal_open(payload_primitive.payload, receiver_crypto_public_key,
      receiver_crypto_secret_key)
  end
  def unseal_payload(_message, _crypto_public_key, _crypto_secret_key), do: :error_malformed_message

  def verify_signature(%Message{envelope: envelope, payload: payload,
      signature: %CD_dashC_BigAttachmentGroup{cesr_elements: [
        %CD_dashK_BigControllerIdxSigs{cesr_elements: [signature]}
      ]}}, sender_sig_public_key) do
    text_to_sign = Cesr.produce_text_stream([envelope, payload])
    case :libsodium_crypto_sign_ed25519.verify_detached(signature.payload, text_to_sign, sender_sig_public_key) do
      0 -> :true  # (it's a port of a C API)
      _ -> :false
    end
  end
  def verify_signature(_message, _sig_public_key), do: :error_malformed_message

  def to_b64(%Message{envelope: envelope, payload: payload, signature: signature}) do
    # have to wrap it or it's not a valid count code...
    with {:ok, wrapped_message} <- CD_A_GenericGroup.new([envelope, payload, signature]) do
      Cesr.produce_text_stream([wrapped_message])
    end
  end
  def to_b64(_message), do: :error_malformed_message

  def from_b64(bytes) do
    with {:ok, %CD_A_GenericGroup{cesr_elements: [envelope, payload, signature]}}
           <- Cesr.consume_primitive_T(bytes) do
      %Message{envelope: envelope, payload: payload, signature: signature}
    end
  end
end
