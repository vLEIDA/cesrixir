defmodule Cesr.MixProject do
  use Mix.Project

  @source_url "https://github.com/vLEIDA/cesrixir"
  @version "1.0.1"

  def project do
    [
      app: :cesrixir,
      version: @version,
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      docs: [
        nest_modules_by_prefix: [Cesr,
          Cesr.Primitive,
          Cesr.Primitive.Indexes,
          Cesr.Primitive.Generator,
          Cesr.Index,
          Cesr.Utility,
          Cesr.CodeTable,
          Cesr.CountCode.Generator,
          Cesr.CountCodeKERIv1,
          Cesr.CountCodeKERIv2 ]
      ],
      package: [
        description: "An implementation of the CESR encoding/decoding protocol (versions 1 and 2) of KERI protocol/genus 1.0 and 2.0 tables.",
        licenses: ["MIT"],
        links: %{"GitHub" => @source_url},
        maintainers: ["daidoji", "dc7"]
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:msgpack, "~> 0.8.1"},
      {:ord_map, "~> 0.1.0"},
      {:jason, "~> 1.4"},
      # Our own version of scalpel-software/cbor on hex.pm that
      # has support for OrdMap serialization/deserialization.
      {:cbor, "~> 1.0", hex: :cbor_ordmap},
      {:dialyxir, "~> 1.4", only: [:dev], runtime: false},
      {:ex_doc, "0.39.1", only: [:dev], runtime: false}
    ]
  end
end
