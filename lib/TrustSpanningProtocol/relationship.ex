defmodule TSP.Relationship do
  alias TSP.Keystore
  alias TSP.Relationship

  @enforce_keys [:our_vid, :their_vid, :our_keystore, :their_keystore, :their_pid]
  defstruct     [:our_vid, :their_vid, :our_keystore, :their_keystore, :their_pid]

  def new(our_vid) do
    %Relationship{
      our_vid: our_vid,
      their_vid: :nil,
      our_keystore: Keystore.random(),
      their_keystore: Keystore.new(),
      their_pid: :nil
    }
  end
end
