/*******************************************************************************
 * Copyright (c) 2016, SVV Lab, University of Luxembourg
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * 3. Neither the name of acmate nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/
package org.svv.acmate.burpsuite;

import java.lang.Thread.UncaughtExceptionHandler;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import org.svv.GlobalConstants;
import org.svv.acmate.gui.ISiteMapListener;
import org.svv.acmate.model.Request;
import org.svv.acmate.model.RequestHeader;
import org.svv.acmate.model.filters.Filters;
import org.svv.acmate.utils.PermissionUtil;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;

public class SiteMap {

	private List<Request> allRequests;
	
	private Map<String, List<Request>> pathRequestsMap;
	private List<String> paths;
	private Map<String, Boolean> selectedPaths;
	
	public Map<String, Boolean> getSelectedPaths() {
		return selectedPaths;
	}

	private IBurpExtenderCallbacks callbacks;
	
	private boolean updated = false; 
	
    List<ISiteMapListener> siteMapListeners;
    List<ISiteMapProgressListener> loadingListeners;
    	
	public List<Request> getAllRequests() {
		return allRequests;
	}

	public Map<String, List<Request>> getPathRequestsMap() {
		return pathRequestsMap;
	}
	
	public List<String> getPaths() {
		return paths;
	}

	public SiteMap(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		allRequests = new LinkedList<Request>();
		
		pathRequestsMap = new HashMap<String, List<Request>>();
		selectedPaths = new HashMap<String, Boolean>();
		paths = new ArrayList<String>();
		
    	siteMapListeners = new ArrayList<ISiteMapListener>();
    	
    	loadingListeners = new ArrayList<ISiteMapProgressListener>();
	}
	
	public void registerSiteMapLoadingListener(ISiteMapProgressListener listerner){
		synchronized(loadingListeners) {
			loadingListeners.add(listerner);
		}
	}
	
	public void deregisterSiteMapLoadingListener(ISiteMapProgressListener listerner){
		synchronized(loadingListeners) {
			loadingListeners.remove(listerner);
		}
	}
	
	/**
	 * Register a sitemap listener
	 * @param listerner
	 */
	public void registerSiteMapListener(ISiteMapListener listerner){
		siteMapListeners.add(listerner);
	}
	
	
	/**
	 * Notify listener about changes
	 * @param eventType
	 */
	public void siteMapChanged(String eventType){
		if (ISiteMapListener.EVENT_SITEMAP_UPDATED.equals(eventType)){
			for (ISiteMapListener l : siteMapListeners){
				l.siteMapUpdated();
			}
		}
	}

	/**
	 * Populate allRequests and their relationship based on a chosen root note in
	 * Burpsuite sitemap
	 * 
	 * @param root
	 */
	public void populate(final IHttpRequestResponse burpRoot) {
		
		Runnable runable = new Runnable(){
			 
		    @Override
		    public void run(){
				if (burpRoot == null)
					return;
		
				allRequests.clear();
				
				pathRequestsMap.clear();
				paths.clear();
				selectedPaths.clear();
				
				IExtensionHelpers helper = callbacks.getHelpers();
		
				Request root = extract(burpRoot, helper);
				String urlPrefix = root.getUrl().toString();
		
				// add request to the list
				allRequests.add(root);
				addToMap(root);
		
				IHttpRequestResponse[] allRequestResponse = callbacks.getSiteMap(urlPrefix);
				if (allRequestResponse.length == 0 && root.getUrl().getPort() == 80){
					// have to remove :80 port from the url prefix
					urlPrefix = urlPrefix.replaceFirst(":80", "");
					allRequestResponse = callbacks.getSiteMap(urlPrefix);
				}
				if (allRequestResponse.length > 0) {
					
					informLoadingStart(allRequestResponse.length);
					int progress = 1;
					for (IHttpRequestResponse burpRR : allRequestResponse) {
						Request request = extract(burpRR, helper);
						allRequests.add(request);
						addToMap(request);
						
						informLoadingProgress(progress++);
					}
				}
		
				// determine relationship among allRequests
				if (allRequests.size() > 0) {
					
					informLoadingStart(allRequests.size());
					int progress = 1;
					
					Iterator<Request> iter1 = allRequests.iterator();
					while (iter1.hasNext()) {
						
						Request request = iter1.next();
						Iterator<Request> iter2 = allRequests.iterator();
						while (iter2.hasNext()) {
							Request predecesor = iter2.next();
							if (request != predecesor) {
								String referer = request.getHeader().getReferer();
								if (referer != null
										&& referer.equals(predecesor.getUrl()
												.toString())) {
									request.addPredecesor(predecesor);
								}
							}
						}
						
						informLoadingProgress(progress++);
					}
				}
				informLoadingDone();
				updated = true;
				
				// notify listeners
				siteMapChanged(ISiteMapListener.EVENT_SITEMAP_UPDATED);
		   }
		};
		
		
		Thread t = new Thread(runable);
		Thread.setDefaultUncaughtExceptionHandler(new UncaughtExceptionHandler() {
			@Override
			public void uncaughtException(Thread t, Throwable e) {
				callbacks.issueAlert("Failed to polulate the sitemap");
				e.printStackTrace();
			}
		});
		t.start();
		
	}

	private void informLoadingDone() {
		for (ISiteMapProgressListener l : loadingListeners){
			if (l != null)
				l.done();
		}
	}

	private void informLoadingProgress(int worked) {
		for (ISiteMapProgressListener l : loadingListeners){
			if (l != null)
				l.progress(worked);
		}
	}

	private void informLoadingStart(int totalLoad) {
		for (ISiteMapProgressListener l : loadingListeners){
			if (l != null)
				l.start(totalLoad);
		}
	}

	/**
	 * Add a request to the path-request map
	 * @param root
	 */
	private void addToMap(Request request) {
		
		String requestPath = request.getUrl().getPath();
		if (GlobalConstants.REMOVE_ENDING_SLASH && requestPath.endsWith("/"))
			requestPath = requestPath.substring(0, requestPath.length() - 1); // remove the last slash
		
		if (pathRequestsMap.containsKey(requestPath)){
			pathRequestsMap.get(requestPath).add(request);
		} else {
			List<Request> newList = new LinkedList<Request>();
			newList.add(request);
			pathRequestsMap.put(requestPath, newList);
			paths.add(requestPath);
		}
	}

	/**
	 * Extract a request from IHttpRequestResponse
	 * 
	 * @param burpRR
	 * @param helper
	 * @return
	 */
	private Request extract(final IHttpRequestResponse burpRR,
			final IExtensionHelpers helper) {
		Request request = new Request();
		request.setOriginalSource(Request.REQUEST_SOURCE_PROXY);
		
		IRequestInfo requestInfo = helper.analyzeRequest(burpRR);
		request.setUrl(requestInfo.getUrl());
		request.setHeader(new RequestHeader(requestInfo.getHeaders()));
		request.setMethod(requestInfo.getMethod());
		request.setBurpRR(burpRR);

		for (IParameter p : requestInfo.getParameters()) {
			request.addParam(new BurpParameter(p.getName(), p.getValue(), p.getType()));
		}

		return request;
	}

	public boolean isUpdated() {
		return updated;
	}

	public void setUpdated(boolean updated) {
		this.updated = updated;
	}

	/**
	 * Color burpsuite requests based on the filters defined in filterModel
	 * @param filterModel
	 */
	public void colorBurpsuiteRecord(final Filters filterModel) {
		Runnable coloringTask = new Runnable(){
			 
		    @Override
		    public void run(){
		    	synchronized(allRequests){
		    		
		    		informLoadingStart(allRequests.size());
		    		
		    		int progress = 1;
			        for (Request r : allRequests){
			        	IHttpRequestResponse rr = r.getBurpRR();
			        	
			        	String color = PermissionUtil.getColor(filterModel, rr, callbacks.getHelpers());
			        	if (color.equals(PermissionUtil.COLOR_GREEN)){
			        		rr.setHighlight("green");
			        	} else if (color.equals(PermissionUtil.COLOR_RED)){
			        		rr.setHighlight("red");
			        	} else if (color.equals(PermissionUtil.COLOR_ORANGE)){
		        			// multiple conflicting rules have been applied applied
		        			rr.setHighlight("orange");
		        			rr.setComment("ACMate: conflicting filters applied!");
			        	} else {
			        		rr.setHighlight(null);
			        	}
			        	
			        	r.setColor(color);
			        	
			        	informLoadingProgress(progress++);
			        }
			        informLoadingDone();
			        callbacks.issueAlert("Done applying AC filters");
		    	}
		    }


		};
		 
		Thread t = new Thread(coloringTask);
		Thread.setDefaultUncaughtExceptionHandler(new UncaughtExceptionHandler() {
			
			@Override
			public void uncaughtException(Thread t, Throwable e) {
				callbacks.issueAlert("Failed to apply filtering, something was wrong!");
				e.printStackTrace();
			}
		});
		t.start();
	}

}
