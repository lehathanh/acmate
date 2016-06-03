package burp;

import org.svv.acmate.ACMateBurpExtender;


public class BurpExtender implements IBurpExtender {

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		callbacks.registerContextMenuFactory(new ACMateBurpExtender(callbacks));
	}

}
