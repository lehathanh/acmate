package org.svv.acmate.model;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.svv.acmate.executor.Session;
import org.svv.acmate.gui.IModelListener;
import org.svv.acmate.model.config.Authentication;
import org.svv.acmate.model.config.Configuration;
import org.svv.acmate.model.config.PageExtToExclude;
import org.svv.acmate.model.config.User;
import org.svv.acmate.model.filters.Filter;
import org.svv.acmate.model.filters.Filters;
import org.svv.acmate.model.filters.StatusCodePattern;
//import org.svv.weka.ACPolicyModel;

import burp.IHttpRequestResponse;

public class TargetAppModel {
	
	protected String startURL;
	protected String workingDir;
	protected IHttpRequestResponse rootRR;
	
	public IHttpRequestResponse getRootRR() {
		return rootRR;
	}

	public String getWorkingDir() {
		return workingDir;
	}

	public void setWorkingDir(String workingDir) {
		this.workingDir = workingDir;
	}

	protected Configuration configModel;
	protected Filters filterModel;
	protected Map<User,Boolean> activeUsers;
	
	protected List<Session> executionResults;
//	protected ACPolicyModel acPolicyModel;
	
    List<IModelListener> modelListeners;

	
	/** --------------------------------------------------------------------- **
	 * Setter and Getters
	 * @return
	 */
	public String getStartURL() {
		return startURL;
	}

	public void setStartURL(String startURL) {
		this.startURL = startURL;
		modelChanged(IModelListener.EVENT_START_URL_CHANGED);
	}

	public void setRootRR(IHttpRequestResponse selectedRoot) {
		this.rootRR = selectedRoot;
	}

	public TargetAppModel() {
		
    	// init the listerners
    	modelListeners = new ArrayList<IModelListener>();
		
		activeUsers = new HashMap<User, Boolean>();
		
		filterModel = new Filters();
		configModel = new Configuration();
		initDefault();
	}
	
    
    /**
     * Register view to be notified when the start URL is changed
     * @param 
     */
	public void registerModelListener(IModelListener listener) {
		modelListeners.add(listener);
	}
	
	/**
	 * Notify listeners about data updated
	 * 
	 * @param eventType
	 */
	public void modelChanged(String eventType){
		if (IModelListener.EVENT_START_URL_CHANGED.equals(eventType)){
			for (IModelListener l : modelListeners){
				l.startURLChanged();
			}
		} 
		
		if (IModelListener.EVENT_USERS_CHANGED.endsWith(eventType)){
			for (IModelListener l : modelListeners){
				l.usersChanged();
			}
		}

		if (IModelListener.EVENT_FILTERS_CHANGED.endsWith(eventType)){
			for (IModelListener l : modelListeners){
				l.filterChanged();
			}
		}

		if (IModelListener.EVENT_USERS_RELOADED.endsWith(eventType)){
			for (IModelListener l : modelListeners){
				l.configReloaded();
			}
		}
		
		if (IModelListener.EVENT_FILTERS_RELOADED.endsWith(eventType)){
			for (IModelListener l : modelListeners){
				l.filterReloaded();
			}
		}

		if (IModelListener.EVENT_TESTRESULT_UPDATED.endsWith(eventType)){
			for (IModelListener l : modelListeners){
				l.testResultUpdated();
			}
		}
	}

	public Configuration getConfigModel() {
		return configModel;
	}

	public void setConfigModel(Configuration configModel) {
		this.configModel = configModel;
		activeUsers.clear();
		modelChanged(IModelListener.EVENT_USERS_RELOADED);
	}

	public Filters getFilterModel() {
		return filterModel;
	}
	
	/**
	 * get 
	 * @return
	 */
//	public ACPolicyModel getACPolicyModel() {
//		
//		if (acPolicyModel == null)
//			acPolicyModel = new ACPolicyModel();
//		
//		return acPolicyModel;
//	}
	

	public List<Session> getExecutionResults() {
		// FIXME: fix this lock
//		synchronized (executionResults)
//		{
		if (executionResults == null){
			executionResults = new ArrayList<Session>();
		}
//		}
		return executionResults;
	}

	public Map<User, Boolean> getActiveUsers() {
		return activeUsers;
	}

	public void setFilterModel(Filters filterModel) {
		this.filterModel = filterModel;
		modelChanged(IModelListener.EVENT_FILTERS_RELOADED);
	}

	private void initDefault() {
		User u = new User();
		u.setUsername("admin");
		u.setPassword("1234");
		u.setRole("administrator");
		
		configModel.getUser().add(u);
		
		Authentication auth = new Authentication();
		auth.setUserFieldName("username");
		auth.setPasswordFieldName("password");
		configModel.setAuthentication(auth);
		
		List<PageExtToExclude> extList = configModel.getPageExtToExclude();

		PageExtToExclude ext = new PageExtToExclude();
		ext.setValue("css");
		extList.add(ext);
		
		ext = new PageExtToExclude();
		ext.setValue("gif");
		extList.add(ext);

		ext = new PageExtToExclude();
		ext.setValue("png");
		extList.add(ext);

		ext = new PageExtToExclude();
		ext.setValue("jpg");
		extList.add(ext);

		ext = new PageExtToExclude();
		ext.setValue("js");
		extList.add(ext);
		
		Filter f = new Filter();
		StatusCodePattern codePattern =  new StatusCodePattern();
		codePattern.setValue("200");
		codePattern.setMatched(true);
		
		f.setStatusCodePattern(codePattern);
		f.setPermission(Filter.FILTER_PERMISSION_ALLOWED);
		filterModel.getFilter().add(f);
		
		f = new Filter();
		codePattern =  new StatusCodePattern();
		codePattern.setValue("40.?");
		codePattern.setMatched(true);
		
		f.setStatusCodePattern(codePattern);
		f.setPermission(Filter.FILTER_PERMISSION_DENIED);
		filterModel.getFilter().add(f);

		f = new Filter();
		codePattern =  new StatusCodePattern();
		codePattern.setValue("301");
		codePattern.setMatched(true);
		
		f.setStatusCodePattern(codePattern);
		f.setPermission(Filter.FILTER_PERMISSION_DENIED);
		filterModel.getFilter().add(f);
	}
}
