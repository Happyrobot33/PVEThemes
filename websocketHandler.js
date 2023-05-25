var socket;
var ticket;
var requestString;

async function sendShellCommand(requestStringVar) {
	protocol = (location.protocol === 'https:') ? 'wss://' : 'ws://';
	requestString = requestStringVar;

	var params = {};
	var url = '/nodes/' + Proxmox.NodeName;
	return new Promise((resolve, reject) => {
		API2Request({
			method: 'POST',
			params: params,
			url: url + '/termproxy',
			success: function (result) {
				var port = encodeURIComponent(result.data.port);
				ticket = result.data.ticket;
				socketURL = protocol + location.hostname + ((location.port) ? (':' + location.port) : '') + '/api2/json' + url + '/vncwebsocket?port=' + port + '&vncticket=' + encodeURIComponent(ticket);

				socket = new WebSocket(socketURL, 'binary');
				socket.binaryType = 'arraybuffer';
				socket.onopen = handleSocket;
				socket.onclose = resolve;
				socket.onerror = reject;
			},
			failure: function (msg) {
				console.log(msg);
			}
		});
	});
}

function handleSocket() {
	//we need to send a log in message first
	socket.send(Proxmox.UserName + ":" + ticket + "\n");

	var messageSent = false;

	//we need to wait for the console to be ready
	socket.onmessage = function (event) {
		var answer = new Uint8Array(event.data);
		var answerString = String.fromCharCode.apply(null, answer);
		//OK check
		if (answerString.indexOf("OK") !== -1) {
			//wait for the console to be ready
			setTimeout(() => {
				var length = requestString.length;
				socket.send("0:" + length + ":" + requestString);
				socket.send("0:1:\r\n");
				messageSent = true;
			}, 500);
		}

		//check if we see an escape char in the console
		if (answerString.includes("[?2004h")) {
			if (messageSent) {
				socket.close();
			}
		}
	}
}


function API2Request(reqOpts) {
	var me = this;

	reqOpts.method = reqOpts.method || 'GET';

	var xhr = new XMLHttpRequest();

	xhr.onload = function () {
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
	var i, value, params = [];

	for (i in object) {
		if (object.hasOwnProperty(i)) {
			value = object[i];
			if (value === undefined) value = '';
			params.push(encodeURIComponent(i) + '=' + encodeURIComponent(String(value)));
		}
	}

	return params.join('&');
}
