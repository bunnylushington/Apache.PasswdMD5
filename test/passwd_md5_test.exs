defmodule PasswdMD5Test do
  use ExUnit.Case
  alias Apache.PasswdMD5, as: MD

  @salt "01234567"
  @pass "password"
  @md5     "$1$01234567$b5lh2mHyD2PdJjFfALlEz1"
  @apr  "$apr1$01234567$IXBaQywhAhc0d75ZbaSDp/"
  @apr_magic "$apr1$"

  test "extract salt" do
    assert MD.extract_salt!(@apr) == @salt
    assert MD.extract_salt!(@md5) == @salt
    assert_raise RuntimeError, fn -> MD.extract_salt!("random string") end
    assert {:ok, @salt} = MD.extract_salt(@apr)
    assert {:ok, @salt} = MD.extract_salt(@md5)
    assert {:error, nil} = MD.extract_salt("random string")
  end

  test "extract or generate salt" do
    assert MD.extract_or_generate_salt(@apr) == @salt
    assert MD.extract_or_generate_salt(@md5) == @salt
    assert String.length(MD.extract_or_generate_salt("random string")) == 8
  end

  test "maybe extract salt" do
    assert MD.maybe_extract_salt(@md5) == "01234567"
    assert MD.maybe_extract_salt(@apr) == "01234567"
  end

  test "final hash" do
    assert MD.hexstring(MD.final_hash(@pass, @salt)) ==
                "fa378024840d64806b718f4a4d8156fe"
  end

  test "open hash" do
    expected = "ab6d0c341626e787f355057c41477721"
    ctx = MD.open_hash(@pass, @salt, @apr_magic)
    final = :crypto.hash_final ctx
    assert MD.hexstring(final) == expected
  end

  test "step one" do
    expected = "1e71014620d18d36fac8c0c7e745af65"
    ctx   = MD.open_hash(@pass, @salt, @apr_magic)
    final = MD.final_hash(@pass, @salt)
    res   = MD.step_one(String.length(@pass), ctx, final)
    intermediate = :crypto.hash_final res
    assert MD.hexstring(intermediate) == expected
  end

  test "step two" do
    expected = "11ffba86fed62f12f2b34e864fa48617"
    ctx = MD.open_hash(@pass, @salt, @apr_magic)
    final = MD.final_hash(@pass, @salt)
    ctx = MD.step_one(String.length(@pass), ctx, final)
    res = MD.step_two(String.length(@pass), @pass, ctx)
    assert MD.hexstring(res) == expected
  end

  test "step three" do
    expected = "98b70a943da7d8cf8b72e975d49c4c69"
    final = MD.final_hash(@pass, @salt)
    ctx   = MD.open_hash(@pass, @salt, @apr_magic)
    ctx            = MD.step_one(String.length(@pass), ctx, final)
    finalized_ctx  = MD.step_two(String.length(@pass), @pass, ctx)
    last_round_ctx = MD.step_three(finalized_ctx, @salt, @pass, 0) 
    assert MD.hexstring(last_round_ctx) == expected
  end    

  # test "crypt" do
  #   {:ok, magic, salt, pw, _entry} = MD.unix_md5_crypt(@md5)
  #   assert magic == "$1$"
  #   assert salt == @salt
  #   assert pw == @md5

  #   {:ok, magic, salt, pw, _entry} = MD.apache_md5_crypt(@apr)
  #   assert magic == "$apr1$"
  #   assert salt == @salt
  #   assert pw == @apr
  # end

  test "apache crypt" do
    {:ok, magic, salt, pw, ht_string} = MD.apache_md5_crypt(@pass, @salt)
    assert magic == @apr_magic
    assert salt == @salt
    assert pw == @pass
    assert ht_string == @apr

    # if a string with a magic pattern is passed, extract the salt for use
    assert {:ok, ^magic, ^salt, ^pw, ^ht_string} = 
      MD.apache_md5_crypt(@pass, ht_string)
    
  end

  test "to_64" do
    # values snarfed from Perl implementation
    assert MD.to_64(4253963, 4) == "9YCE"
    assert MD.to_64(11550095, 4) == "Dq1g"
    assert MD.to_64(11934526, 4) == "ygVh"
    assert MD.to_64(10671875, 4) == "1Qhc"
    assert MD.to_64(2866927, 4) == "jvv8"
    assert MD.to_64(107, 2) == "f/"
  end


end
