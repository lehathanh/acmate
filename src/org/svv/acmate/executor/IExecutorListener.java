package org.svv.acmate.executor;

import java.util.List;

public interface IExecutorListener {
	
	public void start(int load);
	public void start(List<Session> sessions);
	
	public void done();
	public void failed(String message);
	
	public void progress(int complete);
	
}
