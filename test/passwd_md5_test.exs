defmodule PasswdMD5Test do
  use ExUnit.Case
  alias PasswdMD5, as: MD

  @salt "01234567"
  @pass "password"
  @md5  "$1$01234567$b5lh2mHyD2PdJjFfALlEz1"
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

  test "ref hash" do
    assert PasswdMD5.hexstring(PasswdMD5.ref_hash(@pass, @salt)) ==
                       "fa378024840d64806b718f4a4d8156fe"
  end

  test "open hash" do
    expected = "ab6d0c341626e787f355057c41477721"
    ctx = PasswdMD5.open_hash(@pass, @salt, @apr_magic)
    final = :crypto.hash_final ctx
    assert PasswdMD5.hexstring(final) == expected
  end

  test "augment step" do
    expected = "1e71014620d18d36fac8c0c7e745af65"
    ctx   = PasswdMD5.open_hash(@pass, @salt, @apr_magic)
    final = PasswdMD5.ref_hash(@pass, @salt)
    res   = PasswdMD5.augment_hash(String.length(@pass), ctx, final)
    intermediate = :crypto.hash_final res
    assert PasswdMD5.hexstring(intermediate) == expected
  end

  test "bitshift_to_augment step" do
    expected = "11ffba86fed62f12f2b34e864fa48617"
    ctx = PasswdMD5.open_hash(@pass, @salt, @apr_magic)
    final = PasswdMD5.ref_hash(@pass, @salt)
    ctx = PasswdMD5.augment_hash(String.length(@pass), ctx, final)
    res = PasswdMD5.bitshift_to_augment(String.length(@pass), @pass, ctx)
    intermediate = :crypto.hash_final res
    assert PasswdMD5.hexstring(intermediate) == expected
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
