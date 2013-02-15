require 'rbnacl'
require 'forwardable'

module Semiprivate
  def self.prepare_key(key)
    key = key.dup
    if RUBY_VERSION >= '1.9.0'
      key[0]  = (key[0].ord  & 248).chr
      key[31] = (key[31].ord & 127 | 64).chr
    else
      key[0] &= 248
      key[31] = key[31] & 127 | 64
    end
    key
  end

  def self.bytes_to_num(bytes)
    bytes.unpack('H*')[0].to_i(16)
  end

  def self.num_to_bytes(num)
    [num.to_s(16)].pack("H*")
  end

  class WriteKey
    extend Forwardable

    attr_reader :seed, :private_scalar, :private_data, :read_key
    def_delegators :read_key, :verify_key

    def initialize(seed, encoding = :raw)
      @seed = Crypto::Encoder[encoding].decode(seed)
      Crypto::Util.check_length(@seed, Crypto::NaCl::SECRETKEYBYTES, "seed")

      digest = Crypto::Hash.sha512(@seed)
      left_half, right_half = digest[0, 32], digest[32, 64]

      original_scalar  = Semiprivate.prepare_key(left_half)
      @private_data    = right_half

      @read_key = ReadKey.new Crypto::Point.base.mult(original_scalar).to_s

      original_scalar    = Semiprivate.bytes_to_num(original_scalar)
      semiprivate_scalar = Semiprivate.bytes_to_num(@read_key.semiprivate_scalar)
      private_scalar     = original_scalar * semiprivate_scalar % Crypto::STANDARD_GROUP_ORDER

      private_scalar_bytes = Semiprivate.num_to_bytes(private_scalar)
      missing_zeros = Crypto::NaCl::SECRETKEYBYTES - private_scalar_bytes.bytesize
      private_scalar_bytes = Crypto::Util.prepend_zeros(missing_zeros, private_scalar_bytes)

      @private_scalar = private_scalar_bytes
    end
  end

  class ReadKey
    attr_reader :semiprivate_key, :semiprivate_scalar, :symmetric_key, :verify_key

    def initialize(key, encoding = :raw)
      @semiprivate_key = Crypto::Encoder[encoding].decode(key)
      Crypto::Util.check_length(@semiprivate_key, Crypto::NaCl::PUBLICKEYBYTES, "semiprivate key")

      digest = Crypto::Hash.sha512(@semiprivate_key)
      left_half, right_half = digest[0, 32], digest[32, 64]

      @semiprivate_scalar = Semiprivate.prepare_key(left_half)
      @symmetric_key      = right_half

      @verify_key = Crypto::VerifyKey.new Crypto::Point.new(@semiprivate_key).mult(@semiprivate_scalar)
    end
  end
end