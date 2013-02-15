require 'spec_helper'

describe Semiprivate::WriteKey do
  let(:write_key_bytes) { "A" * 32 }

  it "calculates verify keys" do
    write_key = described_class.new(write_key_bytes)
    
    expected_verify_key = Crypto::Point.base.mult(write_key.private_scalar).to_s(:hex)
    actual_verify_key   = write_key.verify_key.to_s(:hex)

    expected_verify_key.should eq actual_verify_key
  end
end