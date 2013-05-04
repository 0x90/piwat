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
  module Extension

    # Checks to see if extension is set inside the configuration
    # @param [String] ext the extension key
    # @return [Boolean] whether or not the extension exists in BeEF's configuration
    def self.is_present(ext)
      return BeEF::Core::Configuration.instance.get('beef.extension').has_key?(ext.to_s)
    end

    # Checks to see if extension is enabled in configuration
    # @param [String] ext the extension key
    # @return [Boolean] whether or not the extension is enabled 
    def self.is_enabled(ext)
      return (self.is_present(ext) and BeEF::Core::Configuration.instance.get('beef.extension.'+ext.to_s+'.enable') == true)
    end

    # Checks to see if extension has been loaded
    # @param [String] ext the extension key
    # @return [Boolean] whether or not the extension is loaded 
    def self.is_loaded(ext)
      return (self.is_enabled(ext) and BeEF::Core::Configuration.instance.get('beef.extension.'+ext.to_s+'.loaded') == true)
    end

    # Loads an extension 
    # @param [String] ext the extension key
    # @return [Boolean] whether or not the extension loaded successfully
    # @todo Wrap the require() statement in a try catch block to allow BeEF to fail gracefully if there is a problem with that extension - Issue #480
    def self.load(ext)
      if File.exists?('extensions/'+ext+'/extension.rb')
        require 'extensions/'+ext+'/extension.rb'
        print_debug "Loaded extension: '#{ext}'"
        BeEF::Core::Configuration.instance.set('beef.extension.'+ext+'.loaded', true)
        return true
      end
      print_error "Unable to load extension '#{ext}'"
      return false
    end
  end
end
