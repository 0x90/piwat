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
#
#
require 'twitter'

module BeEF
module Extension
module Notifications
module Channels
  
  class Tweet

    #
    # Constructor
    #
    def initialize(username, message)
      @config = BeEF::Core::Configuration.instance

      # configure the Twitter client
      Twitter.configure do |config|
        config.consumer_key       = @config.get('beef.extension.notifications.twitter.consumer_key')
        config.consumer_secret    = @config.get('beef.extension.notifications.twitter.consumer_secret')
        config.oauth_token    = @config.get('beef.extension.notifications.twitter.oauth_token')
        config.oauth_token_secret = @config.get('beef.extension.notifications.twitter.oauth_token_secret')
      end

      begin
        Twitter.direct_message_create(username, message)
      rescue
        print "Twitter send failed, verify tokens have Read/Write/DM acceess..\n"
      end
    end
  end
  
end
end
end
end

