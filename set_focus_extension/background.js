function tabHandler(tabs) {
	chrome.tabs.sendMessage(tabs[0].id, 
		{action: "set_focus"}, 
		function(response){});
}

chrome.commands.onCommand.addListener(function(command) {
	// alert("uh");
	if (command == "set_focus") {
		chrome.tabs.query({active: true, currentWindow: true}, tabHandler);
	}
});

