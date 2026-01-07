defmodule TSP.Keystore do
  alias TSP.Keystore

  @enforce_keys [:sig_public_key, :sig_secret_key, :crypto_public_key, :crypto_secret_key]
  defstruct     [:sig_public_key, :sig_secret_key, :crypto_public_key, :crypto_secret_key]

  def new() do
    %Keystore{
      sig_public_key: :nil,
      sig_secret_key: :nil,
      crypto_public_key: :nil,
      crypto_secret_key: :nil
    }
  end

  def random() do
    # converting as per https://libsodium.gitbook.io/doc/advanced/ed25519-curve25519
    # can also use two different keypairs
    with {sig_public_key, sig_secret_key}       <- :libsodium_crypto_sign_ed25519.keypair()
    do
      %Keystore{
        sig_public_key:    sig_public_key,
        sig_secret_key:    sig_secret_key,
        crypto_public_key: :libsodium_crypto_sign_ed25519.pk_to_curve25519(sig_public_key),
        crypto_secret_key: :libsodium_crypto_sign_ed25519.sk_to_curve25519(sig_secret_key)
      }
    end
  end
end
