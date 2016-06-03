package org.svv.acmate.gui.handlers;

import java.awt.Component;

import org.svv.acmate.burpsuite.SiteMap;
import org.svv.acmate.gui.IMainController;
import org.svv.acmate.model.TargetAppModel;

public abstract class AbstractSiteMapEventHandler implements IEventHandler {

	IMainController controller;
	TargetAppModel model;
	SiteMap siteMap;
	Component parent;
	
	@Override
	public abstract void handle();

	public AbstractSiteMapEventHandler(IMainController controller,
			TargetAppModel model, SiteMap siteMap, Component parent) {
		this.controller = controller;
		this.model = model;
		this.siteMap = siteMap;
		this.parent = parent;
	}
}
