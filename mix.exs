defmodule PasswdMD5.Mixfile do
  use Mix.Project

  def project do
    [app: :apache_passwd_md5,
     version: "1.0.0",
     elixir: "~> 1.0.0-rc1",
     description: description,
     package: package,
     deps: deps]
  end

  def description do
    """
    Provides Apache/APR style password hashing.  Useful for generating or 
    authenticating against MD5 htpasswd passwords.
    """
  end
  
  def package do
    [
     files: ["lib", "mix.exs", "README*", "test"],
     contributors: ["Kevin Montuori"],
     licenses: ["MIT"],
     links: %{"GitHub" => "https://github.com/kevinmontuori/Apache.PasswdMD5"}]
  end

  def application do
    [applications: [:logger]]
  end

  defp deps do
    []
  end
end
