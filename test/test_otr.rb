gem "minitest"
require "minitest/autorun"
require "tempfile"
require "otr"

class TestOTR < Minitest::Test
  def setup
    @keyfile = Tempfile.new("keys")
    @state = OTR::UserState.new
  end

  def teardown
    @keyfile.unlink
  end

  def test_generate_and_find    
    @state.generate_privkey "test@test", "icq", @keyfile.path
    assert @state.find_privkey("test@test", "icq")
    assert @state.find_privkey("notfound@test", "icq").nil?
  end

  def test_read
    @state.generate_privkey "test@test", "icq", @keyfile.path
    state2 = OTR::UserState.new(keyfile: @keyfile.path)
    key1 = @state.find_privkey("test@test", "icq")
    key2 = state2.find_privkey("test@test", "icq")
    assert key2
    assert_equal key1.fingerprint, key2.fingerprint
  end

  def test_forget
    @state.generate_privkey "test@test", "icq", @keyfile.path
    key = @state.find_privkey("test@test", "icq")
    key.forget!
    assert @state.find_privkey("test@test", "icq").nil?
  end

  def test_forget_all
    @state.generate_privkey("test1@test", "icq", @keyfile.path)
    @state.generate_privkey("test2@test", "icq", @keyfile.path)
    @state.forget_all!
    assert @state.find_privkey("test1@test", "icq").nil?
    assert @state.find_privkey("test2@test", "icq").nil?
  end

  def test_create_client
    state = OTR::UserState.new
    client = state.create_client do
      protocol "icq"
      max_message_size 10
      frag_policy :send_all
    end
    assert_equal "icq", client.protocol
    assert_equal 10, client.max_message_size
    assert_equal :send_all, client.frag_policy
  end
end
