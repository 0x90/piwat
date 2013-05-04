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
# Internal Network Fingerprinting
# Discover devices and applications in the internal network of the victim using
# signatures like default logo images/favicons (partially based on the Yokoso idea).
# It does this by loading images on common/predefined local network
# IP addresses then matching the image width, height and path to those
# for a known device.
#
# TODO LIST
# Add IPv6 support
# Add HTTPS support
# -  Devices with invalid certs are blocked by IE and FF by default
# Improve stealth
# -  Load images with CSS "background:" CSS to avoid http auth login popups
# Improve speed
# -  Detect local ip range first - using browser history and/or with java
#    - History theft via CSS history is patched in modern browsers.
#    - Local IP theft with Java is slow and may fail


class Internal_network_fingerprinting < BeEF::Core::Command
  
  def self.options
    return [
        {'name' => 'ipRange', 'ui_label' => 'Scan IP range (C class)', 'value' => '192.168.0.1-192.168.0.254'},
        {'name' => 'ports', 'ui_label' => 'Ports to test', 'value' => '80,8080'}
    ]
  end
  
  def post_execute
    content = {}
    content['discovered'] = @datastore['discovered'] if not @datastore['discovered'].nil?
    content['url'] = @datastore['url'] if not @datastore['url'].nil?
    if content.empty?
      content['fail'] = 'No devices/applications have been discovered.'
    end
    save content
  end
end
