package org.svv.acmate.gui;

public interface IModelListener {
	public static final String EVENT_START_URL_CHANGED = "Model-StartURL-Changed";
	public static final String EVENT_USERS_CHANGED = "Model-Users-Changed";
	public static final String EVENT_FILTERS_CHANGED = "Model-Filters-Changed";
	public static final String EVENT_USERS_RELOADED = "Model-Users-Reloaded";
	public static final String EVENT_FILTERS_RELOADED = "Model-Filters-Reloaded";
	public static final String EVENT_TESTRESULT_UPDATED = "Model-Test-Results-Updated";
	
	public void startURLChanged();
	
	public void usersChanged();
	
	public void filterChanged();

	public void configReloaded();
	
	public void filterReloaded();
	
	public void testResultUpdated();
}
