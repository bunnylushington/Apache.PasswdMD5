defmodule PasswdMD5 do

  @magic_md5 "$1$"
  @magic_apr "$apr1$"
  @atoz  "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

  def apache_md5_crypt(pw, salt), do: unix_md5_crypt(pw, salt, "$apr1$")

  def unix_md5_crypt(pw, salt, magic \\ "$1$") do
  end


  def extract_salt(str) do
    {_, salt, _} = parse_hash(str)
    if salt == nil, do: {:error, nil}, else: {:ok, salt}
  end

  def extract_salt!(str) do
    case extract_salt(str) do
      {:ok, salt} -> salt
      {:error, nil} -> raise "Valid salt not found in string #{ str }."
    end
  end

  def extract_or_generate_salt(str) do
    case extract_salt(str) do
      {:ok, salt} -> salt
      _ -> generate_salt
    end
  end

  defp generate_salt(length \\ 8, seed \\ :os.timestamp) do
    :random.seed(seed)
    len = String.length(@atoz)
    chr = for _ <- 1 .. length, do: String.at(@atoz, (:random.uniform(len) - 1))
    Enum.join chr
  end

  defp parse_hash(str) do
    magic_part = "(#{ Regex.escape @magic_md5 }|#{ Regex.escape @magic_apr })"
    salt_part = "([^\\$]{0,8})\\$"
    regex = Regex.compile! "^#{magic_part}#{salt_part}(.+)$"
    case Regex.run(regex, str, capture: :all_but_first) do
      [@magic_md5, salt, crypted_pw] -> {:md5, salt, crypted_pw}
      [@magic_apr, salt, crypted_pw] -> {:apr, salt, crypted_pw}
      _                              -> {:invalid_hash, nil, nil}
    end
  end

end