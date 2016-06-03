package org.svv.acmate.executor;

import org.svv.acmate.burpsuite.SiteMap;
import org.svv.acmate.model.TargetAppModel;

import burp.IBurpExtenderCallbacks;

public class ExecutorFactory {
	
	public static final int TESTING_MODE_CRAWLING = 1;
	public static final int TESTING_MODE_RUN_WITH_EXISTING_REQUESTS = 2;
	public static final int TESTING_MODE_RUN_WITH_XINPUT = 3;

	public static ACTestExecutor createExecutor(int executionType
			, final TargetAppModel appModel
			, final SiteMap siteMap
			, final IBurpExtenderCallbacks callbacks){
		
		if (executionType == TESTING_MODE_CRAWLING)
			return new MultiPagesSpider(callbacks, siteMap, appModel);
		
		else if (executionType == TESTING_MODE_RUN_WITH_XINPUT)
			return new ACTestWithXinputExecutor(callbacks, siteMap, appModel);
		
		// default
		return new ACTestExistingRequestsExecutor(callbacks, siteMap, appModel);
		
	}

}
