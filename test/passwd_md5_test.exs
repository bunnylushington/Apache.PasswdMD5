defmodule PasswdMD5Test do
  use ExUnit.Case
  alias PasswdMD5, as: MD

  @salt "01234567"
  @pass "password"
  @md5  "$1$01234567$b5lh2mHyD2PdJjFfALlEz1"
  @apr  "$apr1$01234567$IXBaQywhAhc0d75ZbaSDp/"


  test "the truth" do
    assert 1 + 1 == 2
  end

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


end
