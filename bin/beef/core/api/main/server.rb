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
module API
module Server

    # @note Defined API Paths
    API_PATHS = {
        'mount_handler' => :mount_handler,
        'pre_http_start' => :pre_http_start
    }
    
    # Fires just before the HTTP Server is started
    # @param [Object] http_hook_server HTTP Server object
    def pre_http_start(http_hook_server); end
    
    # Fires just after handlers have been mounted
    # @param [Object] server HTTP Server object
    def mount_handler(server); end
    
    # Mounts a handler
    # @param [String] url URL to be mounted
    # @param [Class] http_handler_class the handler Class
    # @param [Array] args an array of arguments
    # @note This is a direct API call and does not have to be registered to be used
    def self.mount(url, http_handler_class, args = nil)
      BeEF::Core::Server.instance.mount(url, http_handler_class, *args)
    end

    # Unmounts a handler
    # @param [String] url URL to be unmounted
    # @note This is a direct API call and does not have to be registered to be used
    def self.unmount(url)
        BeEF::Core::Server.instance.unmount(url)
    end

  
end
end
end
