gem "minitest"
require "minitest/autorun"
require "tempfile"
require "otr"

class TestAliceAndBob < Minitest::Test
  def setup
    @alice_keyfile = Tempfile.new("keys_alice")
    @bob_keyfile = Tempfile.new("keys_bob")
    @alice_instagfile = Tempfile.new("instags_alice")
    @bob_instagfile = Tempfile.new("bob_alice")

    @inbox = inbox = { "alice" => [], "bob" => [] }
    client_config = proc do
      protocol "icq"
      max_message_size 1000
      frag_policy :send_all

      inject do |from, to, message|
        inbox[to.name] << [from.name, message]
      end
    end

    @alice_state = OTR::UserState.new(keyfile: @alice_keyfile.path, instagfile: @alice_instagfile.path)
    @alice_state.generate_privkey "alice", "icq"
    @alice_client = @alice_state.create_client &client_config
    @alice = @alice_client.add_account("alice")
    @alice.add_contact("bob")

    @bob_state = OTR::UserState.new(keyfile: @bob_keyfile.path, instagfile: @bob_instagfile.path)
    @bob_state.generate_privkey "bob", "icq"
    @bob_client = @bob_state.create_client &client_config
    @bob = @bob_client.add_account("bob")
    @bob.add_contact("alice")
  end

  def teardown
    @alice_keyfile.unlink
    @bob_keyfile.unlink
  end

  def handle_inbox(buddy)
    messages = @inbox[buddy.name]
    @inbox[buddy.name] = []
    log = []
    messages.each do |from, message|
      buddy.receive!(from, message) do |msg,ctx|
        log << [from, msg]
      end
    end
    return log
  end

  def exchange(first, second)
    log = []
    while not @inbox[first.name].empty? or not @inbox[second.name].empty?
      log += handle_inbox(first)
      log += handle_inbox(second)
    end
    return log
  end

  def fixture_1
    [
      ["alice", "hello bob!"],
      ["bob", "hello alice!"],
      ["alice", "goodbye, bob! and thanks for all the fish!"]
    ]
  end

  def chat_session(fixture)
    @alice.send!("bob", "go otr") # alice starts the chat
    exchange(@bob, @alice)
    log = []
    fixture.each do |from, message|
      sender, recipient = if from == "alice"
        [@alice, @bob]
      else
        [@bob, @alice]
      end
      sender.send!(recipient.name, message)
      log += exchange(recipient, sender)
    end
    return log
  end

  def test_opportunistic_opportunistic
    @alice.find_contact("bob").policy = :opportunistic
    @bob.find_contact("alice").policy = :opportunistic
    assert_equal fixture_1, chat_session(fixture_1)
  end

  def test_opportunistic_manual
    @alice.find_contact("bob").policy = :opportunistic
    @bob.find_contact("alice").policy = :manual
    assert_equal fixture_1, chat_session(fixture_1)
  end

  def test_always_manual
    @alice.find_contact("bob").policy = :always
    @bob.find_contact("alice").policy = :manual
    assert_equal fixture_1, chat_session(fixture_1)
  end

  def test_always_always
    @alice.find_contact("bob").policy = :always
    @bob.find_contact("alice").policy = :always
    assert_equal fixture_1, chat_session(fixture_1)
  end

  def test_manual_never
    @alice.find_contact("bob").policy = :manual
    @bob.find_contact("alice").policy = :never
    assert_equal fixture_1, chat_session(fixture_1)
  end

  def test_always_never
    @alice.find_contact("bob").policy = :always
    @bob.find_contact("alice").policy = :never
    @alice.send!("bob", "go otr")
    log = exchange(@bob, @alice)
    assert_match /has requested/, log[0][1]
  end

end