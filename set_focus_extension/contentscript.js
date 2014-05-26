function setFocus() { 
	//document.getElementById("to-english").checked=true;
	document.getElementById("search-french-english").focus(); 
	// console.log("set focus"); 
}

setFocus(); 

chrome.extension.onMessage.addListener(function(msg, sender, sendResponse) {
	// console.log("message received"); 
	if (msg.action == 'set_focus') { 
		setFocus();
	} 
});
