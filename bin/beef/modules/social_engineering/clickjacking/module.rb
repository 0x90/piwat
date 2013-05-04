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
class Clickjacking < BeEF::Core::Command
  
	def self.options
		configuration = BeEF::Core::Configuration.instance
		uri = "http://#{configuration.get("beef.http.host")}:#{configuration.get("beef.http.port")}/demos/clickjack.html"
		return [
			{ 'name' => 'url', 'description' => 'Target URL', 'ui_label' => 'Target URL', 'value' => uri, 'width'=>'400px' },
			{ 'name' => 'offset_top', 'description' => 'Offset Top (in pixels)', 'ui_label' => 'Offset Top (px)', 'value' => '-40', 'width'=>'150px' },
			{ 'name' => 'offset_left', 'description' => 'Offset Left (in pixels)', 'ui_label' => 'Offset Left (px)', 'value' => '-10', 'width'=>'150px' },
			{ 'name' => 'debug', 'type' => 'combobox', 'ui_label' => 'Debug Mode', 'store_type' => 'arraystore', 'store_fields' => ['debug'], 'store_data' => [['true'],['false']], 'valueField' => 'debug', 'value' => 'false', editable: false, 'displayField' => 'debug', 'mode' => 'local', 'autoWidth' => true }
		]
	end

	def post_execute
		content = {}
		content['clickjack'] = @datastore['clickjack']
		save content
	end
  
end
