package org.svv.acmate.executor;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

import org.svv.acmate.burpsuite.SiteMap;
import org.svv.acmate.exception.ExecutorException;
import org.svv.acmate.model.Request;
import org.svv.acmate.model.TargetAppModel;
import org.svv.acmate.model.config.User;
import org.svv.acmate.utils.JAXBUtil;
import org.svv.datagenerator.PairWiseGenerator;
import org.svv.xinput.DomainInputs;
import org.svv.xinput.Page;

import burp.IBurpExtenderCallbacks;

public class ACTestWithXinputExecutor extends ACTestExecutor {

	public ACTestWithXinputExecutor(IBurpExtenderCallbacks callbacks,
			SiteMap siteMap, TargetAppModel appModel) {
		super(callbacks, siteMap, appModel);
	}

	@Override
	public void execute() throws ExecutorException {
		
		List<String> selectedPaths = new ArrayList<String>();
		List<User> selectedUsers = new ArrayList<User>();
		
		if (!isExecutionReady(selectedPaths, selectedUsers)){
			return;
		}
		
		// check xinput file
		String xinputPath = appModel.getWorkingDir() + File.separator + "xinput.xml";
		File f = new File(xinputPath);
		if (!f.exists())
			throw new ExecutorException("xinput.xml file does not exist in the working directory!"); 
		
		DomainInputs domainInputs = JAXBUtil.loadDomainInputs(xinputPath);
		if (domainInputs == null)
			throw new ExecutorException("Cannot load xinput file, please make sure it is valid and welformed!");
		
		if (appModel.getStartURL() == null){
			throw new ExecutorException("Start URL has not been set yet!");
		}
		
		URL startPage;
		try {
			startPage = new URL(appModel.getStartURL());
		} catch (MalformedURLException e) {
			throw new ExecutorException("Start URL is malformed!");
		}
		String basedURL = appModel.getStartURL().replace(startPage.getPath(), "");
		
		// now generate request for the selected pages
		PairWiseGenerator requestGenerator = new PairWiseGenerator();
		List<Request> allNewRequest = new LinkedList<Request>();
		for (String p : selectedPaths){
			for (Page page : domainInputs.getPage()){
				if (p.equals(page.getUrlPath())){
					List<Request> newRequests = requestGenerator.generate(page, basedURL);
					if (newRequests != null && newRequests.size() > 0)
						allNewRequest.addAll(newRequests);
					break; // done this page
				}
			}
		}
		
		if (allNewRequest.size() == 0){
			throw new ExecutorException("Cannot get any existing requests, execution aborted!");
		}
		// sessions
		List<Session> sessions = prepareSessions(selectedUsers, allNewRequest);
		// start execution
		notifyStartExecution(sessions);
		
		// start testing in an independent thread
		startACTest(sessions);
	}

}
