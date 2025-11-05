defmodule Cesr.SadPath do
  @moduledoc """
  A module that implements sadpath.

  Doing this all with OrdMaps at the moment just for an implementation but
  probably need to implement a protocol or behavior so that this can be used on
  things that are OrdMaps underneath (like KERI event structs or ACDC structs)
  without having to cast to ordmap
  """

  @spec resolve_path(OrdMap.t(), binary()) :: {:ok, any()} | {:error, term()}
  @doc """
    Resolves a sadpath into an OrdMap structure
  """
  def resolve_path(%OrdMap{} = m, potential_sad_path)
    when is_binary(potential_sad_path)
  do
    case String.split(potential_sad_path, "-") do
      [""] -> {:error, "Sad path malformed, no dashes #{potential_sad_path}"}
      ["" , ""] -> {:ok, m} # Root is always a path and must go first if that's all there is
      ["" | split_path] -> _resolve_path(split_path, m)
      _ -> {:error, "Sad path malformed #{potential_sad_path}"}
    end
  end

  defp _resolve_path([potential_index | rest], list_of_elements)
    when is_list(list_of_elements)
  do
    case Integer.parse(potential_index) do
      {index, ""} ->
        case Enum.at(list_of_elements, index, :not_found) do
          :not_found -> {:error, "There is no field #{inspect(index)} in #{inspect(list_of_elements)}"}
          element -> _resolve_path(rest, element)
        end
      _ -> {:error, "Index #{inspect(potential_index)} malformed"}
    end
  end
  defp _resolve_path([idx_or_field | rest], %OrdMap{} = m) do
    # See tests for example of bullshit in that for maps you assume indexes first and then field names for some reason
    case get_at_ordmap_index(idx_or_field, m) do
      :outofbounds -> case OrdMap.get(m, idx_or_field, :not_found) do
          :not_found -> {:error, "There is no field or idx @ #{inspect(idx_or_field)} in #{inspect(m)}"}
          element -> _resolve_path(rest, element)
        end
      element -> _resolve_path(rest, element)
    end
  end
  defp _resolve_path([potential_index], list_of_elements)
    when is_list(list_of_elements)
  do
    case Integer.parse(potential_index) do
      {index, ""} ->
        case Enum.at(list_of_elements, index, :not_found) do
          :not_found -> {:error, "There is no field #{inspect(index)} in #{inspect(list_of_elements)}"}
          element -> {:ok, element}
        end
      _ -> {:error, "Index #{inspect(potential_index)} malformed"}
    end
  end
  defp _resolve_path([idx_or_field], %OrdMap{} = m) do
    # See tests for example of bullshit in that for maps you assume indexes first and then field names for some reason
    case get_at_ordmap_index(idx_or_field, m) do
      :outofbounds -> case OrdMap.get(m, idx_or_field, :not_found) do
          :not_found -> {:error, "There is no field or idx @ #{inspect(idx_or_field)} in #{inspect(m)}"}
          element -> {:ok, element}
        end
      element -> {:ok, element}
    end
  end
  defp _resolve_path([], element), do: {:ok, element}
  defp _resolve_path(x, y) do
    {:error, "Either path malformed: #{inspect(x)} or #{inspect(y)} not list or map that aligns with that path"}
  end

  defp get_at_ordmap_index(potential_index, %OrdMap{tuples: tuples}) do
    case Integer.parse(potential_index) do
      {index, ""} -> case Enum.at(tuples, index) do
        {_k, v} -> v
        :nil -> :outofbounds
      end
      _ -> :outofbounds
    end
  end
end
