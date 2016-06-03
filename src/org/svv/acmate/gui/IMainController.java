package org.svv.acmate.gui;

public interface IMainController {
	
	public static final String STARTPANEL_EVENT_EXPORT_DOT = "_view_export_to_DOT";
	public static final String STARTPANEL_EVENT_INIT_CONFIG = "_view_init_config";
	public static final String STARTPANEL_EVENT_EXPORT_XINPUT = "_view_export_xinput";
	public static final String STARTPANEL_EVENT_APPLY_FILTERS = "_view_apply_fiters";
	public static final String STARTPANEL_EVENT_WORKINGDIR_CHANGED = "_view_workingdir_changed";

	
	public static final String ACTESTING_EVENT_STARTTEST = "_view_start_testing";
	public static final String ACTESTING_EVENT_LOAD_SESSIONS = "_view_load_sessions";
	public static final String ACTESTING_EVENT_SAVE_SESSIONS = "_view_save_sessions";
	public static final String ACTESTING_EVENT_CLEAR_SESSIONS = "_view_clear_sessions";;
	
	
	/**
	 * called when controller wants to update views
	 * 
	 * @param eventType
	 */
//	public void fireChange(String eventType);
	
	/**
	 * Called to handle event sent from view to controller
	 * @param eventType
	 */
	public void handleEvent(String eventType);

	/**
	 * handle event
	 * @param eventType
	 * @param option
	 * @return 0 if successful, -1 if failed
	 */
	public int handleEvent(String eventType, int option);
	
	
}
