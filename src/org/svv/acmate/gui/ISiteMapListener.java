package org.svv.acmate.gui;

public interface ISiteMapListener {
	
	public static final String EVENT_SITEMAP_UPDATED = "SiteMap-Updated";

	
	/**
	 * Listener is informed when the sitemap is updated
	 */
	public void siteMapUpdated();
	
}
