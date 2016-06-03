package org.svv.acmate.gui;

public interface IPolicyController {
	public static final String POLICYPANEL_EVENT_INFERPOLICY_SESSIONS = "_view_infer_policy_session";
	public static final String POLICYPANEL_EVENT_INFERPOLICY_PROXYLOGS = "_view_infer_policy_proxy";
	public static final String POLICYPANEL_EVENT_EXPORTRESULT = "_view_export_policy";

	
	/**
	 * Called to handle event sent from view to controller
	 * @param eventType
	 */
	public void handleEvent(String eventType);
}
