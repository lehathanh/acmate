package org.svv.acmate.executor;

public interface ISessionListener {
	public void sessionStart(Session s, int load);
	public void sessionDone(Session s);
	public void sessionProgress(Session s, int complete);
}
