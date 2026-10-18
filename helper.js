function send(data) {
	try {
		ws.send(data);
	} catch (e) {
        void(0);
	}
}

function log(...args) {
	var msg = args.map(function (a) {
		return a === undefined ? 'undefined' : a.toString();
	}).join('');
	send(msg);
	document.getElementById("log").innerHTML += ""+msg+"</br>";
}