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
module Models

  # @todo move this table into the AdminUI extension folder.
  class User
  
    include DataMapper::Resource
  
    storage_names[:default] = 'extension_adminui_users'
    
    property :id, Serial
    property :session_id, String, :length => 255
    property :ip, Text
  
    # Checks if the user has been authenticated
    # @return [Boolean] If the user is authenticated
    def authenticated?
      true || false if not @ip.nil?
    end
  
  end

end
end
end
