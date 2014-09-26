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
    hash = make_hash(pw, salt, magic)
    {:ok, magic, salt, pw, magic <> salt <> "$" <> hash} 
  end

  def hexstring(<< x :: 128 >>) do
    List.to_string(:lists.flatten(:io_lib.format("~32.16.0b", [x])))
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
    ctx = :crypto.hash_update ctx, salt
    ctx
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

  def step_three(ctx, _, _, 0), do: ctx
  def step_three(ctx, salt, pw, count) do
    tmp = :crypto.hash_init(:md5)
    :crypto.hash_update tmp, 
            (if (count &&& 1), do: pw, else:  binary_part(ctx, 0, 16))
    if (rem(count, 3) != 0), do: :crypto.hash_update(tmp, salt)
    if (rem(count, 7) != 0), do: :crypto.hash_update(tmp, pw)
    :crypto.hash_update tmp,
            (if (count &&& 1), do: binary_part(ctx, 0, 16), else: pw)
    step_three(:crypto.hash_final(tmp), salt, pw, (count - 1))
  end

  def d, do: make_hash("password", "01234567", "$apr1$")

  def make_hash(pw, salt, magic) do
    final = final_hash(pw, salt)
    ctx = open_hash(pw, salt, magic)
    ctx = step_one(String.length(pw), ctx, final)
    finalized_ctx = step_two(String.length(pw), pw, ctx)
#    finalized_ctx = :crypto.hash_final ctx
    last_round_ctx = step_three(finalized_ctx, salt, pw, 1000)

    IO.puts hexstring(last_round_ctx)

    # ctx = :crypto.hash_final ctx

    # IO.puts "context; #{ inspect ctx }"
    # ctx = slowdown(ctx, salt, pw, 1000)
    # encode_password(ctx)
  end



  defp encode_password(ctx) do
    # XXX: stupidly naive implementation.
    IO.puts "context: #{ (byte_size ctx) * 8 }"
    {int_1, _ } = Integer.parse(binary_part(ctx, 0,  1) <<< 16)
    {int_2, _ } = Integer.parse(binary_part(ctx, 6,  1) <<< 8)
    {int_3, _ } = Integer.parse(binary_part(ctx, 12, 1))
    res_1 = to_64( (int_1 ||| int_2 ||| int_3), 4 )

    {int_1, _ } = Integer.parse(binary_part(ctx, 1,  1) <<< 16)
    {int_2, _ } = Integer.parse(binary_part(ctx, 7,  1) <<< 8)
    {int_3, _ } = Integer.parse(binary_part(ctx, 13, 1))
    res_2 = to_64( (int_1 ||| int_2 ||| int_3), 4 )

    {int_1, _ } = Integer.parse(binary_part(ctx, 2,  1) <<< 16)
    {int_2, _ } = Integer.parse(binary_part(ctx, 8,  1) <<< 8)
    {int_3, _ } = Integer.parse(binary_part(ctx, 14, 1))
    res_3 = to_64( (int_1 ||| int_2 ||| int_3), 4 )

    {int_1, _ } = Integer.parse(binary_part(ctx, 3,  1) <<< 16)
    {int_2, _ } = Integer.parse(binary_part(ctx, 9,  1) <<< 8)
    {int_3, _ } = Integer.parse(binary_part(ctx, 15, 1))
    res_4 = to_64( (int_1 ||| int_2 ||| int_3), 4 )

    {int_1, _ } = Integer.parse(binary_part(ctx, 4,  1) <<< 16)
    {int_2, _ } = Integer.parse(binary_part(ctx, 10,  1) <<< 8)
    {int_3, _ } = Integer.parse(binary_part(ctx, 5, 1))
    res_5 = to_64( (int_1 ||| int_2 ||| int_3), 4 )
    
    res_6 = to_64(Integer.parse(binary_part(ctx, 11, 1)), 2)

    Enum.join [res_1, res_2, res_3, res_4, res_5, res_6]
  end

  def to_64(value, iterations, chars \\ "")
  def to_64(_, 0, chars), do: chars
  def to_64(value, iterations, chars) do
    to_64 (value >>> 6), (iterations - 1), 
      chars <> String.at(@atoz, (value &&& 0x3f))
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