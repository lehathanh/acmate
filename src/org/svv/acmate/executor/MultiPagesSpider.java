package org.svv.acmate.executor;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import org.svv.acmate.burpsuite.SiteMap;
import org.svv.acmate.exception.ExecutorException;
import org.svv.acmate.model.TargetAppModel;

import burp.IBurpExtenderCallbacks;

public class MultiPagesSpider extends ACTestExecutor {

	public MultiPagesSpider(IBurpExtenderCallbacks callbacks, SiteMap siteMap,
			TargetAppModel appModel) {
		super(callbacks, siteMap, appModel);
	}

	/**
	 * Send all selected pages to Burpsuite's spider
	 */
	@Override
	public void execute() throws ExecutorException {
		
		if (siteMap == null){
			throw new ExecutorException("Site map cannot be null!");
		}
		
		try {
			URL startPage = new URL(appModel.getStartURL());
			String urlPrefix = appModel.getStartURL().replace(startPage.getPath(), "");
		
			List<String> selectedList = new ArrayList<String>();
			for (String path : siteMap.getPaths()){
				Boolean val = siteMap.getSelectedPaths().get(path);
				
				if (val != null && val.booleanValue()){
					// the page path has been selected, send to spider
					String toSpider = urlPrefix + path;
					selectedList.add(toSpider);
				}
			}
			
			if (selectedList.size() == 0){
				throw new ExecutorException("No target page has been selected!");
			}
			
			// start spidering
			notifyStartExecution(selectedList.size());
			for (int i = 0; i < selectedList.size(); i++){
				String toSpider = selectedList.get(i);
				callbacks.sendToSpider(new URL(toSpider));
				informProgress(i+1);
			}
			
			// end spidering
			notifyDoneExecution();
			
		} catch (MalformedURLException e) {
			throw new ExecutorException("Start page URL is not correct!");
		}
		
	}


}
