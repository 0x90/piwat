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
WelcomeTab = function() {

    welcome = " \
              <div style='font:11px tahoma,arial,helvetica,sans-serif;width:500px' > \
              <p><img src='/ui/media/images/beef.jpg' alt='BeEF - The Browser Exploitation Framework' /></p><br /> \
              <p>Official website: <a href='http://beefproject.com/'>http://beefproject.com/</a></p><br />\
              <p><span style='font:bold 13px tahoma,arial,helvetica,sans-serif'>Getting Started</span></p><br />\
              <p>Welcome to BeEF!</p><br /> \
              <p>Before being able to fully explore the framework you will have to 'hook' a browser. To begin with you can point a browser towards the basic demo page <a href='/demos/basic.html' target='_blank'>here</a>, or the advanced version <a href='/demos/butcher/index.html' target='_blank'>here</a>.</p><br /> \
              <p>After a browser is hooked into the framework they will appear in the 'Hooked Browsers' panel on the left. Hooked browsers will appear in either an online or offline state, depending on how recently they have polled the framework.</p><br /> \
              <p><span style='font:bold 13px tahoma,arial,helvetica,sans-serif'>Hooked Browsers</span></p><br />\
              <p>To interact with a hooked browser simply left-click it, a new tab will appear. \
              Each hooked browser tab has a number of sub-tabs, described below:</p><br /> \
              <ul style=\"margin-left:15px;\"><li><span style='font:bold 11px tahoma,arial,helvetica,sans-serif'>Main:</span> Display information about the hooked browser after you've run some command modules.</li> \
              <li><span style='font:bold 11px tahoma,arial,helvetica,sans-serif'>Logs:</span> Displays recent log entries related to this particular hooked browser.</li> \
              <li><span style='font:bold 11px tahoma,arial,helvetica,sans-serif'>Commands:</span> This tab is where modules can be executed against the hooked browser. This is where most of the BeEF functionality resides. \
              Most command modules consist of Javascript code that is executed against the selected\
              Hooked Browser. Command modules are able to perform any actions that can be achieved\
              through Javascript: for example they may gather information about the Hooked Browser, manipulate the DOM or perform other activities such as exploiting vulnerabilities within the local network of the Hooked Browser.<br /><br />\
              Each command module has a traffic light icon, which is used to indicate the following:<ul>\
              <li><img alt='' src='media/images/icons/green.png'  unselectable='on'> The command module works against the target and should be invisible to the user</li>\
              <li><img alt='' src='media/images/icons/orange.png'  unselectable='on'> The command module works against the target, but may be visible to the user</li>\
              <li><img alt='' src='media/images/icons/grey.png'  unselectable='on'> The command module is yet to be verified against this target</li>\
              <li><img alt='' src='media/images/icons/red.png'  unselectable='on'> The command module does not work against this target</li></ul><br />\
              <li><span style='font:bold 11px tahoma,arial,helvetica,sans-serif'>XssRays:</span> The XssRays tab allows the user to check if links, forms and URI path of the page (where the browser is hooked) is vulnerable to XSS.</li> \
              <li><span style='font:bold 11px tahoma,arial,helvetica,sans-serif'>Rider:</span> The Rider tab allows you to submit arbitrary HTTP requests on behalf of the hooked browser. \
              Each request sent by the Rider is recorded in the History panel. Click a history item to view the HTTP headers and HTML source of the HTTP response.</li></ul><br />\
              <p>You can also right-click a hooked browser to open a context-menu with additional functionality:</p><br /> \
              <ul style=\"margin-left:15px;\">\
              <li><span style='font:bold 11px tahoma,arial,helvetica,sans-serif'>Tunneling Proxy:</span> The Proxy allows you to use a hooked browser as a proxy. Simply right-click a browser from the Hooked Browsers tree to the left and select \"Use as Proxy\". \
              Each request sent through the Proxy is recorded in the History panel in the Rider tab. Click a history item to view the HTTP headers and HTML source of the HTTP response.</li>\
              <li><span style='font:bold 11px tahoma,arial,helvetica,sans-serif'>XssRays:</span> XssRays allows the user to check if links, forms and URI path of the page (where the browser is hooked) is vulnerable to XSS. To customize default settings of an XssRays scan, please use the XssRays tab.</li></ul><br /> \
              <p><span style='font:bold 13px tahoma,arial,helvetica,sans-serif'>Learn More</span></p><br />\
              <p>To learn more about how BeEF works please review the wiki:</p><br />\
              <ul style=\"margin-left:15px;\">\
              <li>Architecture of the BeEF System: <a href='https://github.com/beefproject/beef/wiki/Architecture'>https://github.com/beefproject/beef/wiki/Architecture</a></li>\
              <li>Tunneling Proxy: <a href='https://github.com/beefproject/beef/wiki/Tunneling-Proxy'>https://github.com/beefproject/beef/wiki/Tunneling-Proxy</a></li>\
              <li>XssRays Integration: <a href='https://github.com/beefproject/beef/wiki/XssRays-Integration'>https://github.com/beefproject/beef/wiki/XssRays-Integration</a></li>\
              <li>Writing your own modules: <a href='https://github.com/beefproject/beef/wiki/Command-Module-API'>https://github.com/beefproject/beef/wiki/Command-Module-API</a></li></ul>\
              </div>\
              ";

    WelcomeTab.superclass.constructor.call(this, {
	region:'center',
	padding:'10 10 10 10',
	html: welcome,
	autoScroll: true,
	border: false
    });
};

Ext.extend(WelcomeTab,Ext.Panel, {}); 
