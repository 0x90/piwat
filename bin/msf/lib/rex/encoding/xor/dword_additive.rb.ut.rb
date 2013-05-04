#!/usr/bin/env ruby
# -*- coding: binary -*-

$:.unshift(File.join(File.dirname(__FILE__), '..', '..', '..'))

require 'rex/encoding/xor/dword_additive'
require 'rex/encoding/xor/byte.rb.ut'

module Rex::Encoding::Xor
class DwordAdditive::UnitTest < Byte::UnitTest

	def enc
		DwordAdditive
	end
end
end
