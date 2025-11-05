defmodule Cesr.Utility.Base64Indicies do
  @moduledoc """
  Module for using base64 strings of arbitrary length as integers.

  This module exists mostly because Submarine scientists call things b64 but
  then go off the RFC path that describes b64url encoding to bastardize a
  base64url-like encoding as its commonly understood meaning that you can't
  just use libraries willy-nilly and expect to get the results he gets.

  Python's https://docs.python.org/3/library/base64.html has a god-awful mode
  that doesn't adhere to RFC 4648 and gives you all kinds of weird bullshit
  that lets him do that with some bit manipulation.

  Unfortunately (or fortunately) the elixir and erlang Base library doesn't let
  you do that because they adhere to the RFC so we need these utilities to
  index into his scheme without having to be fiddling bits all the time.
  """

  # Can't remove these yet because we use it in our CESR generator macros
  # The unquote into an AST representation doesn't like bitstrings for some reason
  def get_b64_index_for_char(<<char::utf8>>), do: get_b64_urlsafe_index(char)
  defp get_b64_urlsafe_index(m) when m in ?A..?Z, do: m - ?A
  defp get_b64_urlsafe_index(m) when m in ?a..?z, do: m - ?a + 26
  defp get_b64_urlsafe_index(m) when m in ?0..?9, do: m - ?0 + 52
  defp get_b64_urlsafe_index(?-), do: 62
  defp get_b64_urlsafe_index(?_), do: 63
  defp get_b64_urlsafe_index(m), do: {:error, "Value #{m} not b64 character"}

  @doc """
  This function takes a urlsafe b64 binary representation and returns
  the integer value it represents in the scheme.
  """
  def deserialize_value_in_b64_index_scheme(""), do: {:error, "Can't be empty string"}
  def deserialize_value_in_b64_index_scheme(string_of_b64_chars) 
    when is_binary(string_of_b64_chars)
  do
    num_of_As_to_pad = rem(4 - rem(byte_size(string_of_b64_chars), 4), 4)
    padded_b64_to_byte_boundary = String.duplicate("A", num_of_As_to_pad) <> string_of_b64_chars
    case Base.url_decode64(padded_b64_to_byte_boundary) do
      {:ok, decoded_binary} -> {:ok, :binary.decode_unsigned(decoded_binary)}
      :error -> {:error, "Error base64url decoding #{string_of_b64_chars}"}
    end
  end

  @doc """
  This function takes in a natural number and serializes to a b64
  representation of that integer of length text_serialization_length
  """
  def serialize_value_in_b64_index_scheme(value, text_serialization_length \\ 1)
  def serialize_value_in_b64_index_scheme(value, text_serialization_length) 
    when is_integer(value) and value >= 0 and
    is_integer(text_serialization_length) and text_serialization_length > 0
  do
    _serialize_value_in_b64_index_scheme(value, text_serialization_length)
  end
  def serialize_value_in_b64_index_scheme(value, text_serialization_length) do
    {:error, "Can't serialize #{value} to b64: guard didn't match #{is_integer(value)} or text_serialization_length: #{text_serialization_length} not > 0."}
  end

  defp _serialize_value_in_b64_index_scheme(0, text_serialization_length), do:
    {:ok, String.duplicate("A", text_serialization_length)}
  defp _serialize_value_in_b64_index_scheme(value, text_serialization_length) do
    val_bytes = :binary.encode_unsigned(value, :big)
    num_bytes_to_pad = rem(3 - rem(byte_size(val_bytes), 3), 3)
    bin_to_encode = :binary.join(List.duplicate(<<0>>, num_bytes_to_pad) ++ [val_bytes], <<>>)
    case Base.url_encode64(bin_to_encode) do
      b64_rep when byte_size(b64_rep) == text_serialization_length -> {:ok, b64_rep}
      b64_rep when byte_size(b64_rep) > text_serialization_length -> 
        {maybe_padding, maybe_rep} = String.split_at(b64_rep, -text_serialization_length)
        if String.match?(maybe_padding, ~r/^A+$/) do
          {:ok, maybe_rep}
        else
          {:error, "Value #{value} too big for b64url representation length: #{text_serialization_length}"}
        end
      b64_rep when byte_size(b64_rep) < text_serialization_length -> {:ok,
        String.duplicate("A", text_serialization_length - byte_size(b64_rep)) <> b64_rep}
      #:error -> {:error, "Error serializing #{value} to b64"}
    end
  end

  @doc """
  Gets bits of b64 representation.  
  
  Warning: only to be used in Generators at compile time.  Use non-bang
  version everywhere else.
  """
  @spec bits_of_b64_representation!(String.t()) :: bitstring()
  def bits_of_b64_representation!(code) do
    {:ok, bits} = bits_of_b64_representation(code)
    bits
  end

  @doc """
  Gets bitstring of b64 representation.
  """
  @spec bits_of_b64_representation(String.t()) :: {:ok, bitstring()} | {:error, term()}
  def bits_of_b64_representation(""), do: {:error, "\"\" doesn't seem to be a b64 representation"}
  def bits_of_b64_representation(code)
    when rem(byte_size(code), 4) == 0
  do
    case Base.url_decode64(code) do
      {:ok, decoded_padded_rep} -> {:ok, decoded_padded_rep}
      :error -> {:error, "#{code} doesn't seem to be a b64 representation"}
    end
  end
  def bits_of_b64_representation(code) 
    when is_binary(code)
  do
    num_of_As_to_pad = rem(4 - rem(byte_size(code), 4), 4)
    padded_b64_to_byte_boundary = String.duplicate("A", num_of_As_to_pad) <> code
    case Base.url_decode64(padded_b64_to_byte_boundary) do
      {:ok, decoded_padded_rep} -> 
        size_padding = num_of_As_to_pad * 6
        <<_padding::size(size_padding), rep::bitstring>> = decoded_padded_rep
        {:ok, rep}
      :error -> {:error, "#{code} doesn't seem to be a b64 representation"}
    end
  end
  def bits_of_b64_representation(code), do: {:error, "#{code} doesn't seem to be a b64 representation"}
end
