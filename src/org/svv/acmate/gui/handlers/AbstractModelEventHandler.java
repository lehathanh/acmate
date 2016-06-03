package org.svv.acmate.gui.handlers;

import java.awt.Component;

import org.svv.acmate.gui.IMainController;
import org.svv.acmate.model.TargetAppModel;

public abstract class AbstractModelEventHandler implements IEventHandler {
	
	IMainController controller;
	TargetAppModel model;
	Component parent;
	
	
	@Override
	public abstract void handle();

	public AbstractModelEventHandler(IMainController controller, TargetAppModel model,
			Component parent) {
		this.controller = controller;
		this.model = model;
		this.parent = parent;
	}
}
