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
package org.svv.html;

import java.util.ArrayList;
import java.util.List;

import org.jsoup.Jsoup;
import org.jsoup.nodes.*;
import org.jsoup.select.Elements;

public class HtmlUtil {
	
	private Document doc = null;

	/**
	 * parse an html page
	 * 
	 * @param html
	 */
	public void parse(String html){
		doc = Jsoup.parse(html);
	}
	
	
	/**
	 * extract all value from the parse page for the parameter "paramName"
	 * of the urlPath
	 * 
	 * @param urlPath
	 * @param paramName
	 * @return
	 */
	public List<String> extractValues(String urlPath, String paramName){
		if (doc == null) return null;
		
		List<String> ret = new ArrayList<String>();
		// value from forms
		Elements forms = getForms();
		
		for (Element f : forms){
			if (f.attr("action") != null && f.attr("action").equals(urlPath)){
				 
				// inputs
				List<WebInputElement> inputs = getParameters(f);
				 for (WebInputElement element : inputs){
					 if (element.getName().equals(paramName)){
						 ret.add(element.getValue());
					 }
				 }
				 
				 // selects
				 Elements selects = f.select("select");
				 if (selects != null){
					 for (Element e : selects){
						 String id = "";
						 if (e.attr("name") != null)
							 id = e.attr("name");
						 else if (e.attr("id") != null)
							 id = e.attr("id");
						 if (!id.isEmpty() && id.equals(paramName)){
							 Elements options = e.select("option");
							 for (Element opt : options){
								 ret.add(opt.attr("value"));
							 }
						 }
					 }
				 }
				 
				 // text areas
				 Elements textareas = f.select("textarea");
				 if (selects != null){
					 for (Element e : textareas){
						 if (!e.attr("name").isEmpty() && e.attr("name").equals(paramName)){
							 ret.add(e.text());
						 }
					 }
				 }
			}
		}
		
		 Elements links = doc.select("a[href]");
		 for (Element link : links) {
			 String absLink = link.attr("abs:href");
			 if (absLink.contains(urlPath)){
				 if (absLink.contains(paramName + "="))
				 {
					 int startIndex = absLink.indexOf(paramName + "=");
					 int endIndex = absLink.indexOf("&", startIndex);
					 if (endIndex == -1){
						 endIndex = absLink.length();
					 }
					 String tmp = absLink.substring(startIndex, endIndex);
					 ret.add(tmp.split("=")[1]);
				 }
			 }
		 }
		
		return ret;
	}
	
	/**
	 * Get a list of form names from the parsed html page
	 * 
	 * @return
	 */
	public List<String> getFormNames(){
		if (doc == null) return null;
		
		List<String> ret = new ArrayList<String>();
		
		Elements forms = doc.getElementsByTag("form");
		for (Element f : forms) {
			ret.add(f.attr("name"));
		}
		
		return ret;
	}

	/**
	 * query all forms
	 * @return
	 */
	public Elements getForms(){
		if (doc == null) return null;
		
		Elements forms = doc.getElementsByTag("form");
		return forms;
	}
	
	/**
	 * get list of input web elements from a form
	 * @param form
	 * @return
	 */
	public List<WebInputElement> getParameters(Element form){
		if (form == null)
			return null;
	
		List<WebInputElement> params = new ArrayList<WebInputElement>();
		
		for (Element inputElement : form.getElementsByTag("input")) {
			String name = inputElement.attr("name");
			String value = inputElement.attr("value");
			String id = inputElement.attr("id");
			String type = inputElement.attr("type");
			
			
			params.add(new WebInputElement(id, name, value, type));
		}
	 	return params;
	}
	
	/**
	 * Get a list of input elements from a form
	 * @param formId
	 * @return
	 */
	public List<WebInputElement> getParameters(String formId){
		if (doc == null) return null;
		
		List<WebInputElement> params = new ArrayList<WebInputElement>();
		Element form = doc.getElementById(formId);
		
		
		if (form == null)
			return null;
		
		Elements inputElements = form.getElementsByTag("input");

		for (Element inputElement : inputElements) {
			String name = inputElement.attr("name");
			String value = inputElement.attr("value");
			String id = inputElement.attr("id");
			String type = inputElement.attr("type");
			
			
			params.add(new WebInputElement(id, name, value, type));
		}
	 	return params;
	}
	
}
