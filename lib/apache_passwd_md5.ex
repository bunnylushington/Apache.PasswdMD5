defmodule Apache.PasswdMD5 do

  @moduledoc """
  Provides a means of generating an Apache style MD5 hash (as used by
  htaccess).  This code was derived from the Crypt::PasswdMD5 Perl
  module which appears to have been based on 
  
    http://svn.apache.org/viewvc/apr/apr/trunk/crypto/apr_md5.c?view=co

  Corrections or suggestions welcome.

  # Examples

      iex> {:ok, magic, salt, pw, htstring} =
      ...>     Apache.PasswdMD5.crypt("password", "salt")
      {:ok, "$apr1$", "salt", "password", "$apr1$salt$Xxd1irWT9ycqoYxGFn4cb."}
      
      iex> {:ok, ^magic, ^salt, ^pw, ^htstring} =
      ...>     Apache.PasswdMD5.crypt("password", htstring)
      {:ok, "$apr1$", "salt", "password", "$apr1$salt$Xxd1irWT9ycqoYxGFn4cb."}

  """

  use Bitwise
  require Integer

  @magic_md5 "$1$"
  @magic_apr "$apr1$"
  @atoz  "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

  def crypt(pw, salt \\ nil, magic \\ "$apr1$")  do
    salt = case salt do
             nil -> extract_or_generate_salt pw
             str -> maybe_extract_salt str
           end
    hash = make_hash(pw, salt, magic)
    {:ok, magic, salt, pw, magic <> salt <> "$" <> hash} 
  end

  def make_hash(pw, salt, magic) do
    final          = final_hash(pw, salt)
    ctx            = open_hash(pw, salt, magic)
    ctx            = step_one(String.length(pw), ctx, final)
    finalized_ctx  = step_two(String.length(pw), pw, ctx)
    last_round_ctx = step_three(finalized_ctx, salt, pw, 0) 
    step_four(last_round_ctx)
  end

  def final_hash(pw, salt) do
    ctx  = :crypto.hash_init :md5
    ctx  = :crypto.hash_update ctx, pw
    ctx  = :crypto.hash_update ctx, salt
    ctx  = :crypto.hash_update ctx, pw
    :crypto.hash_final ctx
  end
  
  def open_hash(pw, salt, magic) do
    # note that this isn't finalized.
    ctx = :crypto.hash_init(:md5)
    ctx = :crypto.hash_update ctx, pw
    ctx = :crypto.hash_update ctx, magic
    :crypto.hash_update ctx, salt
  end

  def step_one(place, ctx, _final) when place < 0, do: ctx
  def step_one(place, ctx, final) do
    length = if place > 16, do: 16, else: place
    addition = binary_part(final, 0, length)
    step_one(place - 16, :crypto.hash_update(ctx, addition), final)
  end

  def step_two(len, _pw, ctx) when len == 0, do: :crypto.hash_final ctx
  def step_two(len, pw, ctx) do
    ctx = if ((len &&& 1) != 0) do
            :crypto.hash_update(ctx, <<0>>)
          else
            :crypto.hash_update(ctx, String.first pw)
          end
    step_two((len >>> 1), pw, ctx)
  end

  def step_three(ctx, salt, pw, count) when count < 1000 do
    tmp = :crypto.hash_init(:md5)
    first_update = 
      if Integer.is_odd(count), do: pw, else: binary_part(ctx, 0, 16)
    tmp = :crypto.hash_update tmp, first_update
    if (rem(count, 3) != 0), do: tmp = :crypto.hash_update(tmp, salt)
    if (rem(count, 7) != 0), do: tmp = :crypto.hash_update(tmp, pw)
    second_update = 
      if Integer.is_odd(count), do: binary_part(ctx, 0, 16), else: pw
    tmp = :crypto.hash_update tmp, second_update
    step_three(:crypto.hash_final(tmp), salt, pw, (count + 1))
  end
  def step_three(ctx, _, _, _), do: ctx

  defp step_four(ctx) do
    # XXX: stupidly naive implementation.
    << x0,  x1,  x2,  x3,
       x4,  x5,  x6,  x7, 
       x8,  x9,  x10, x11,
       x12, x13, x14, x15 >> = ctx
    r1 = to_64 ( (x0 <<< 16) ||| (x6  <<< 8) ||| x12 ), 4
    r2 = to_64 ( (x1 <<< 16) ||| (x7  <<< 8) ||| x13 ), 4
    r3 = to_64 ( (x2 <<< 16) ||| (x8  <<< 8) ||| x14 ), 4
    r4 = to_64 ( (x3 <<< 16) ||| (x9  <<< 8) ||| x15 ), 4
    r5 = to_64 ( (x4 <<< 16) ||| (x10 <<< 8) ||| x5  ), 4
    r6 = to_64 x11, 2
    Enum.join [r1, r2, r3, r4, r5, r6]
  end

  def to_64(value, iterations, chars \\ "")
  def to_64(_, 0, chars), do: chars
  def to_64(value, iterations, chars) do
    to_64 (value >>> 6), (iterations - 1), 
      chars <> String.at(@atoz, (value &&& 0x3f))
  end


  def maybe_extract_salt(str) do
    case extract_salt(str) do
      {:ok, salt} -> salt
      _ -> str
    end
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
    chr = for _ <- 1 .. length do 
      String.at(@atoz, (:random.uniform(len) - 1))
    end
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

  def hexstring(<< x :: 128 >>) do
    List.to_string(:lists.flatten(:io_lib.format("~32.16.0b", [x])))
  end

end