package org.svv.acmate;

import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenuItem;

import org.svv.acmate.gui.MainGUI;

import burp.IBurpExtenderCallbacks;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;

public class ACMateBurpExtender implements IContextMenuFactory {
	
	private final IBurpExtenderCallbacks callbacks_;
	private MainGUI gui_ = null;

	public ACMateBurpExtender(IBurpExtenderCallbacks callbacks) {
		this.callbacks_ = callbacks;
		callbacks_.setExtensionName("AC Mate");
    	gui_ = new MainGUI(callbacks_);
    	gui_.setVisible(true);
	}

	@Override
	public List<JMenuItem> createMenuItems(final IContextMenuInvocation invocation) {
		List<JMenuItem> list = new ArrayList<JMenuItem>();
		JMenuItem item = new JMenuItem("Send to AC Mate");

		item.addMouseListener(new MouseListener() {
			@Override
			public void mouseClicked(MouseEvent e) {
			}

			@Override
			public void mousePressed(MouseEvent e) {
				initACMate(invocation.getSelectedMessages());
			}

			@Override
			public void mouseReleased(MouseEvent e) {
			}

			@Override
			public void mouseEntered(MouseEvent e) {
			}

			@Override
			public void mouseExited(MouseEvent e) {
			}
		});
		list.add(item);

		return list;
	}

	/**
	 * 
	 * @param selectedMessages
	 */
	protected void initACMate(IHttpRequestResponse[] selectedMessages) {
		gui_.init(selectedMessages);
		if (!gui_.isVisible())
			gui_.setVisible(true);
	}
	
	

}
