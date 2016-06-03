package org.svv.acmate.burpsuite;

public interface ISiteMapProgressListener {
	public void start(int totalLoad);
	public void progress(int loaded);
	public void done(); 
}
