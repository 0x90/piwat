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
module Evasion
  extend BeEF::API::Extension

  @short_name = 'evasion'
  @full_name = 'Evasion'
  @description = 'Contains Evasion and Obfuscation techniques to prevent the likelihood that BeEF will be detected'
end
end
end

require 'extensions/evasion/evasion'
require 'extensions/evasion/helper'
require 'extensions/evasion/obfuscation/scramble'
require 'extensions/evasion/obfuscation/minify'
require 'extensions/evasion/obfuscation/base_64'
require 'extensions/evasion/obfuscation/whitespace'
