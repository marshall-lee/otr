
module OTR
  VERSION = "1.0.0"

  class GPGError < StandardError; end

  class ConfigDSL
    def initialize(obj)
      @obj = obj
    end

    def method_missing(var, value)
      if @obj.instance_variable_defined? "@#{var}"
        @obj.instance_variable_set "@#{var}", value
      else
        super
      end
    end

    def respond_to_missing?(var)
      @obj.instance_variable_defined?("@#{var}") || super
    end
  end

  class UserState
    attr_reader :keyfile
    attr_reader :instagfile

    def initialize(**options)
      @clients = []
      @keyfile = options[:keyfile]
      @instagfile = options[:instagfile]
      if @keyfile
        read_keys(@keyfile) if File.exist?(@keyfile) and File.size(@keyfile) > 0
      end
    end

    def find_privkey(accountname, protocol)
      begin
        PrivKey.new(self, accountname, protocol)
      rescue
        nil
      end
    end

    def create_client(**options, &block)
      client = Client.new(self, options, &block)
      @clients << client
      client
    end

    def each_client
      @clients.each
    end
  end

  class PrivKey
  end

  class Context < Struct.new(:account, :contact, :our_instance, :their_instance)
    def accountname
      account.name
    end

    def contactname
      contact.name
    end

    alias_method :username, :contactname
  end

  class Client
    attr_reader :protocol
    attr_reader :max_message_size
    attr_reader :frag_policy

    class ClientConfigDSL < ConfigDSL

      def inject(&block)
        @obj.define_singleton_method(:inject, &block)
      end

      def received(&block)
        @obj.define_singleton_method(:received, &block)
      end

      def frag_policy(arg)
        super
        @obj.validate_frag_policy!
      end

      def fragment(arg)
        if arg
          unless @obj.fragment?
            frag_policy :send_all
          end
        else
          if @obj.fragment?
            frag_policy :send_skip
          end
        end
      end
    end

    def initialize(user_state, **options, &block)
      @user_state = user_state
      @accounts = {}

      @protocol = options[:protocol] || :meow
      @frag_policy = options[:frag_policy] || :send_skip
      validate_frag_policy!
      @max_message_size = options[:max_message_size]

      if block_given?
        ClientConfigDSL.new(self).instance_eval(&block)
      end
    end

    def add_account(name, **options)
      @accounts[name] = Account.new(self, name, options)
    end

    def find_account(name)
      @accounts[name]
    end

    def validate_frag_policy!
      policies = [:send_all, :send_all_but_first, :send_all_but_last, :send_skip]
      unless policies.include? @frag_policy
        raise "Invalid frag_policy #{@frag_policy}"
      end
      if @frag_policy == :send_all_but_first or @frag_policy == :send_all_but_last
        raise "frag_policy #{@frag_policy} not supported"
      end
    end

    def fragment?
      @frag_policy != :send_skip
    end

    def send!(account, contact, text, **options, &block)
      instance = options[:instance] || :best
      instance_i = unless instance.instance_of? Integer
        @@meta_instances[instance]
      else
        instance
      end

      frag_policy = options[:frag_policy] || @frag_policy
      frag_policy_i = unless frag_policy.instance_of? Integer
        @@frag_policies_table[frag_policy]
      else
        frag_policy
      end

      account = find_account(account) if account.instance_of? String
      contact = account.find_contact(contact) if contact.instance_of? String

      msg, context = internal_send_message(account.name,
        contact.name,
        text,
        instance_i,
        frag_policy_i)

      if msg == text
        do_inject(account.name, contact.name, text)
      end

      if block_given?
        yield msg, context
      end
      return msg
    end

    def receive!(account, contact, text, **options, &block)
      account = find_account(account) if account.instance_of? String
      contact = account.find_contact(contact) if contact.instance_of? String

      msg, context = internal_receive_message(account.name, contact.name, text)
      if msg
        if block_given?
          yield msg, context
        end
      end
      return msg
    end

    private
      def find_contact(account_name, contact_name)
        account = find_account(account_name)
        if account
          account.find_contact(contact_name)
        end
      end

      def do_inject(account_name, recipient_name, text)
        account = find_account(account_name)
        contact = account.find_contact(recipient_name)
        inject account, contact, text
      end
  end

  class Account
    attr_reader :name

    def initialize(client, name, **options)
      @client = client
      @name = name
      @contacts = {}
    end

    def add_contact(name, **options)
      @contacts[name] = Contact.new(self, name, options)
    end

    def find_contact(name)
      @contacts[name]
    end

    def send!(contact, text, **options, &block)
      @client.send!(self, contact, text, options, &block)
    end

    def receive!(contact, text, **options, &block)
      @client.receive!(self, contact, text, options, &block)
    end
  end

  class Contact
    attr_reader :name
    attr_accessor :policy

    def initialize(account, name, **options)
      @account = account
      @name = name
      @is_logged_in = false
      @policy = options[:policy]
    end

    def logged_in?
      @is_logged_in
    end

    def log_in!
      @is_logged_in = true
    end

    def log_out!
      @is_logged_in = false
    end

    def send!(text, **options, &block)
      @account.send!(self, text, options, &block)
    end

    def receive!(contact, text, **options, &block)
      @account.receive!(self, text, options, &block)
    end
  end
end

require "otr/otr"