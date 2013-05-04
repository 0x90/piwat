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
module BeEF
module Core
module Console

module Banners
  class << self
    attr_accessor :interfaces

    #
    # Prints BeEF's ascii art
    #
    def print_ascii_art
        if File.exists?('core/main/console/beef.ascii')
            File.open('core/main/console/beef.ascii', 'r') do |f|
                while line = f.gets
                    puts line 
                end
            end
        end
    end

    #
    # Prints BeEF's welcome message
    #
    def print_welcome_msg
        config = BeEF::Core::Configuration.instance
        version = config.get('beef.version')
        print_info "Browser Exploitation Framework (BeEF)"
        data =  "Version #{version}\n"
        data += "Website http://beefproject.com\n"
        data += "Run 'beef -h' for basic help.\n"
        data += "Run 'git pull' to update to the latest revision."
        print_more data
    end

    #
    # Prints the number of network interfaces beef is operating on.
    # Looks like that:
    #
    # [14:06:48][*] 5 network interfaces were detected.
    #
    def print_network_interfaces_count
      # get the configuration information
      configuration = BeEF::Core::Configuration.instance
      version = BeEF::Core::Configuration.instance.get('beef.version')
      beef_host = configuration.get("beef.http.public") || configuration.get("beef.http.host") 
    
      # create an array of the interfaces the framework is listening on
      if beef_host == '0.0.0.0' # the framework will listen on all interfaces
        interfaces = Socket.ip_address_list.map {|x| x.ip_address if x.ipv4?}
        interfaces.delete_if {|x| x.nil?} # remove if the entry is nill
      else # the framework will listen on only one interface
        interfaces = [beef_host]
      end
    
      self.interfaces = interfaces
    
      # output the banner to the console
      print_info "#{interfaces.count} network interfaces were detected."
    end
    
    #
    # Prints the route to the network interfaces beef has been deployed on.
    # Looks like that:
    #
    # [14:06:48][+] running on network interface: 192.168.255.1
    # [14:06:48]    |   Hook URL: http://192.168.255.1:3000/hook.js
    # [14:06:48]    |   UI URL:   http://192.168.255.1:3000/ui/panel
    # [14:06:48][+] running on network interface: 127.0.0.1
    # [14:06:48]    |   Hook URL: http://127.0.0.1:3000/hook.js
    # [14:06:48]    |   UI URL:   http://127.0.0.1:3000/ui/panel
    #


    def print_network_interfaces_routes
      configuration = BeEF::Core::Configuration.instance
      prototxt = configuration.get("beef.http.https.enable") == true ? "https" : "http"
      
      self.interfaces.map do |host| # display the important URLs on each interface from the interfaces array
        print_success "running on network interface: #{host}"
        beef_host = configuration.get("beef.http.public_port") || configuration.get("beef.http.port")
        data = "Hook URL: #{prototxt}://#{host}:#{configuration.get("beef.http.port")}#{configuration.get("beef.http.hook_file")}\n"
        data += "UI URL:   #{prototxt}://#{host}:#{configuration.get("beef.http.port")}#{configuration.get("beef.http.panel_path")}\n"
        
        print_more data
      end
    end
    
    #
    # Print loaded extensions
    #
    def print_loaded_extensions
      extensions = BeEF::Extensions.get_loaded
      print_info "#{extensions.size} extensions loaded:"
      output = ''
      
      
      extensions.each do |key,ext|
        output += "#{ext['name']}\n"
      end
      
      print_more output
    end
    
    #
    # Print loaded modules
    def print_loaded_modules
        print_info "#{BeEF::Modules::get_enabled.count} modules enabled."
    end
  end
end

end
end
end
