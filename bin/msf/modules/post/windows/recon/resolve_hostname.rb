##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Windows Recon Resolve Hostname',
				'Description'   => %q{ This module resolves a hostname to IP address via the victim, similiar to the Unix dig command},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Rob Fuller <mubix[at]hak5.org>'],
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'meterpreter' ]
			))

		register_options(
			[
				OptString.new('HOSTNAME', [true, 'Hostname to lookup', nil])
			], self.class)
	end

	def run
		### MAIN ###

		if client.platform =~ /^x64/
			size = 64
			addrinfoinmem = 32
		else
			size = 32
			addrinfoinmem = 24
		end

		hostname = datastore['HOSTNAME']

		## get IP for host
		begin
			vprint_status("Looking up IP for #{hostname}")
			result = client.railgun.ws2_32.getaddrinfo(hostname, nil, nil, 4 )
			if result['GetLastError'] == 11001
				print_error("Failed to resolve the host")
				return
			end
			addrinfo = client.railgun.memread( result['ppResult'], size )
			ai_addr_pointer = addrinfo[addrinfoinmem,4].unpack('L').first
			sockaddr = client.railgun.memread( ai_addr_pointer, size/2 )
			ip = sockaddr[4,4].unpack('N').first
			hostip = Rex::Socket.addr_itoa(ip)
			print_status("#{hostname} resolves to #{hostip}")
		rescue ::Exception => e
			print_error(e)
			print_status('Windows 2000 and prior does not support getaddrinfo')
		end
	end
end
