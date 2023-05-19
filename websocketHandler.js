var socket;
var ticket;
var requestString;

function sendShellCommand(requestStringVar) {
    protocol = (location.protocol === 'https:') ? 'wss://' : 'ws://';
	requestString = requestStringVar;

    var params = {};
    var url = '/nodes/' + Proxmox.NodeName;
    API2Request({
	method: 'POST',
	params: params,
	url: url + '/termproxy',
	success: function(result) {
	    var port = encodeURIComponent(result.data.port);
	    ticket = result.data.ticket;
        //https://aether.matthewherber.com:8007/api2/json/nodes/Aether/termproxy/vncwebsocket?port=8007&vncticket=
	    socketURL = protocol + location.hostname + ((location.port) ? (':' + location.port) : '') + '/api2/json' + url + '/vncwebsocket?port=' + port + '&vncticket=' + encodeURIComponent(ticket);

	    socket = new WebSocket(socketURL, 'binary');
	    socket.binaryType = 'arraybuffer';
	    socket.onopen = handleSocket;
	},
	failure: function(msg) {
	    console.log(msg);
	}
    });
}

function handleSocket() {
	//we need to send a log in message first
	socket.send(Proxmox.UserName + ":" + ticket + "\n");

	//we need to wait for the console to be ready
	socket.onmessage = function(event) {
		var answer = new Uint8Array(event.data);
		//OK check
		if (answer[0] === 79 && answer[1] === 75) {
			//wait a second
			setTimeout(() => {
				var length = requestString.length;
				socket.send("0:" + length + ":" + requestString);
				socket.send("0:1:\r\n");
				setTimeout(() => {
					socket.close();
				}, 1000);
			}, 1000);
		}
	}
}


function API2Request(reqOpts) {
    var me = this;

    reqOpts.method = reqOpts.method || 'GET';

    var xhr = new XMLHttpRequest();

    xhr.onload = function() {
	var scope = reqOpts.scope || this;
	var result;
	var errmsg;

	if (xhr.readyState === 4) {
	    var ctype = xhr.getResponseHeader('Content-Type');
	    if (xhr.status === 200) {
		if (ctype.match(/application\/json;/)) {
		    result = JSON.parse(xhr.responseText);
		} else {
		    errmsg = 'got unexpected content type ' + ctype;
		}
	    } else {
		errmsg = 'Error ' + xhr.status + ': ' + xhr.statusText;
	    }
	} else {
	    errmsg = 'Connection error - server offline?';
	}

	if (errmsg !== undefined) {
	    if (reqOpts.failure) {
		reqOpts.failure.call(scope, errmsg);
	    }
	} else {
	    if (reqOpts.success) {
		reqOpts.success.call(scope, result);
	    }
	}
	if (reqOpts.callback) {
	    reqOpts.callback.call(scope, errmsg === undefined);
	}
    }

    var data = urlEncode(reqOpts.params || {});

    if (reqOpts.method === 'GET') {
	xhr.open(reqOpts.method, "/api2/json" + reqOpts.url + '?' + data);
    } else {
	xhr.open(reqOpts.method, "/api2/json" + reqOpts.url);
    }
    xhr.setRequestHeader('Cache-Control', 'no-cache');
    if (reqOpts.method === 'POST' || reqOpts.method === 'PUT') {
	xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
	xhr.setRequestHeader('CSRFPreventionToken', Proxmox.CSRFPreventionToken);
	xhr.send(data);
    } else if (reqOpts.method === 'GET') {
	xhr.send();
    } else {
	throw "unknown method";
    }
}

function urlEncode(object) {
    var i,value, params = [];

    for (i in object) {
	if (object.hasOwnProperty(i)) {
	    value = object[i];
	    if (value === undefined) value = '';
	    params.push(encodeURIComponent(i) + '=' + encodeURIComponent(String(value)));
	}
    }

    return params.join('&');
}
