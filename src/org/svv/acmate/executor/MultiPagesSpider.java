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
