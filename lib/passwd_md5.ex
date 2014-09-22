defmodule PasswdMD5 do

  use Bitwise

  @magic_md5 "$1$"
  @magic_apr "$apr1$"
  @atoz  "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

  def apache_md5_crypt(pw, salt \\ nil), do: unix_md5_crypt(pw, salt, "$apr1$")

  def unix_md5_crypt(pw, salt \\ nil, magic \\ "$1$") do
    salt = case salt do
             nil -> extract_or_generate_salt pw
             str -> str
           end

    _entry = make_hash(pw, salt, magic)

    {:ok, magic, salt, pw, :not_implemented}
  end

  
  def make_hash(pw, salt, magic) do
    ctx = :crypto.hash_init(:md5)
    ctx = :crypto.hash_update ctx, pw
    ctx = :crypto.hash_update ctx, magic
    ctx = :crypto.hash_update ctx, salt

    final = :crypto.hash_init(:md5)
    final = :crypto.hash_update final, pw
    final = :crypto.hash_update final, salt
    final = :crypto.hash_update final, pw
    final = :crypto.hash_final final
    
    ctx = augment_hash(String.length(pw), ctx, final)
    ctx = bitshift_to_augment(String.length(pw), pw, ctx)
    ctx = :crypto.hash_final ctx

    for i <- 0 .. 999 do
      tmp = :crypto.hash_init(:md5)
      :crypto.hash_update tmp, 
              (if (i &&& 1), do: pw, else:  binary_part(ctx, 0, 16))
      if (rem(i, 3) != 0), do: :crypto.hash_update(tmp, salt)
      if (rem(i, 7) != 0), do: :crypto.hash_update(tmp, pw)
      :crypto.hash_update tmp,
              (if (i &&& 1), do: binary_part(ctx, 0, 16), else: pw)
      ctx = :crypto.hash_final tmp
    end
     
    password = encode_password(ctx)
    
  end

  defp encode_password(ctx) do
    
  end

  # def to_64(value, iterations) do
  #   to_64 value, iterations, []
  #   # characters = for _ <- 1 .. iterations do
  #   #   IO.puts value >>> 6
  #   #   pos = value &&& 0x3f
  #   #   value = value >>> 6
  #   #   String.at @atoz, pos
  #   # end
  #   # Enum.join characters
  # end

  def to_64(value, iterations, chars \\ "")
  def to_64(value, 0, chars), do: chars
  def to_64(value, iterations, chars) do
    to_64 (value >>> 6), (iterations - 1), 
      chars <> String.at(@atoz, (value &&& 0x3f))
  end


  defp bitshift_to_augment(len, _pw, ctx) when len == 0, do: ctx
  defp bitshift_to_augment(len, pw, ctx) do
    ctx = if ((len &&& 1) != 0) do
            :crypto.hash_update(ctx, <<0>>)
          else
            :crypto.hash_update(ctx, String.first pw)
          end
    bitshift_to_augment((len >>> 1), pw, ctx)
  end
    
      

  defp augment_hash(place, ctx, _final) when place < 0, do: ctx
  defp augment_hash(place, ctx, final) do
    length = if place > 16, do: 16, else: place
    addition = binary_part(final, 0, length)
    augment_hash(place - 16, :crypto.hash_update(ctx, addition), final)
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