package org.svv.acmate.gui.handlers;

import java.awt.Component;

import org.svv.acmate.burpsuite.SiteMap;
import org.svv.acmate.gui.IMainController;
import org.svv.acmate.model.TargetAppModel;

public class EventHandlerFactory {
	
	public static IEventHandler createHandler(String eventType, IMainController controller, TargetAppModel model, SiteMap siteMap, Component parent){
	
		if (IMainController.ACTESTING_EVENT_LOAD_SESSIONS.equals(eventType))
			return new LoadTestResultHandler(controller, model, parent);

		if (IMainController.ACTESTING_EVENT_CLEAR_SESSIONS.equals(eventType))
			return new ClearTestResultHandler(controller, model, parent);
	
		if (IMainController.ACTESTING_EVENT_SAVE_SESSIONS.equals(eventType))
			return new SaveTestResultHandler(controller, model, parent);
	
		if (IMainController.STARTPANEL_EVENT_INIT_CONFIG.equals(eventType))
			return new SaveConfigurationHandler(controller, model, parent);
	
		if (IMainController.STARTPANEL_EVENT_WORKINGDIR_CHANGED.equals(eventType))
			return new WorkingDirChangedHandler(controller, model, parent);
	
		if (IMainController.STARTPANEL_EVENT_EXPORT_DOT.equals(eventType))
			return new ExportToDotHandler(controller, model, siteMap, parent);
		
		if (IMainController.STARTPANEL_EVENT_APPLY_FILTERS.equals(eventType))
			return new ApplyFiltersHandler(controller, model, siteMap, parent);
	
		if (IMainController.STARTPANEL_EVENT_EXPORT_XINPUT.equals(eventType))
			return new MineDomainInputsHandler(controller, model, siteMap, parent);
		
		return null;
	}
}
