##
# $Id$
##

##
# ## This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/common'


class Metasploit3 < Msf::Post

	include Msf::Post::Common
	include Msf::Auxiliary::Report


	def initialize(info={})
		super( update_info( info,
				'Name'          => 'Windows Gather TCP Netstat',
				'Description'   => %q{ This Module lists current TCP sessions},
				'License'       => MSF_LICENSE,
				'Author'        => [ 'Rob Fuller <mubix[at]hak5.org>'],
				'Version'       => '$Revision$',
				'Platform'      => [ 'windows' ],
				'SessionTypes'  => [ 'meterpreter']
			))
		register_options(
			[
			], self.class)
	end

	def parse_tcptable(buffer)
		entries = buffer[0,4].unpack("V*")[0]
		print_status("Total TCP Entries: #{entries}")

		rtable = Rex::Ui::Text::Table.new(
			'Header' => 'Connection Table',
			'Indent' => 2,
			'Columns' => ['STATE', 'LHOST', 'LPORT', 'RHOST', 'RPORT']
		)
		offset = 4
		(1..entries).each do
			x = {}
			x[:state] = case buffer[(offset + 0), 4].unpack("V*")[0]
				when 1
					'CLOSED'
				when 2
					'LISTEN'
				when 3
					'SYN_SENT'
				when 4
					'SYN_RCVD'
				when 5
					'ESTABLISHED'
				when 6
					'FIN_WAIT1'
				when 7
					'FIN_WAIT2'
				when 8
					'CLOSE_WAIT'
				when 9
					'CLOSING'
				when 10
					'LAST_ACK'
				when 11
					'TIME_WAIT'
				when 12
					'DELETE_TCB'
				else
					'UNDEFINED'
			end
			x[:lhost] = Rex::Socket.addr_itoa(buffer[(offset + 4), 4].unpack("N")[0])
			x[:lport] = buffer[(offset + 8), 4].unpack("n")[0]
			x[:rhost] = Rex::Socket.addr_itoa(buffer[(offset + 12), 4].unpack("N")[0])
			if x[:state] == "LISTEN"
				x[:rport] = "_"
			else
				x[:rport] = buffer[(offset + 16), 4].unpack("n")[0]
			end
			offset = offset + 20
			rtable << [x[:state], x[:lhost], x[:lport], x[:rhost], x[:rport]]
		end
		print_status(rtable.to_s)
	end

	def run
		session.railgun.add_function('iphlpapi', 'GetTcpTable', 'DWORD', [
		['PBLOB', 'pTcpTable', 'out'],
		['PDWORD', 'pdwSize', 'inout'],
		['BOOL', 'bOrder', 'in']
		])

		getsize = session.railgun.iphlpapi.GetTcpTable(4,4,true)
		buffersize = getsize['pdwSize']

		print_status("TCP Table Size: #{buffersize}")
		tcptable = session.railgun.iphlpapi.GetTcpTable(buffersize,buffersize,true)

		parse_tcptable(tcptable['pTcpTable'])
	end
end
