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
package org.svv.datagenerator;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.JAXBElement;
import org.svv.acmate.burpsuite.BurpParameter;
import org.svv.acmate.model.Request;
import org.svv.xinput.AtomicParam;
import org.svv.xinput.AtomicParamRef;
import org.svv.xinput.ComplexDataSpecType;
import org.svv.xinput.Facet;
import org.svv.xinput.InputType;
import org.svv.xinput.Page;
import org.svv.xinput.SourceType;
import org.svv.xinput.Xinput;
import burp.IParameter;
import uk.co.demon.mcdowella.algorithms.AllPairs;

public class PairWiseGenerator implements IRequestGenerator {
	// default parameter of AllPairs
	private static final boolean SHOULD_SHUFFLE = true;
	private static final int MAX_GOES = 100;
	private static final int MAX_TRY_FOR_IMPROVEMENT = 10;
	private static final long SEED = 42;

	private static final String GENERATOR_NAME = "PW-McDowell";

	/**
	 * Generate test cases for a tree using pairwise technique
	 * Generated test cases are stored in the tree 
	 * 
	 */
	@Override
	public List<Request> generate(Page page, String basedURL) {
		if (page == null)
			return null;

		List<ParamInfo> allParams = extractCTEInfo(page);
		
		if (allParams.size() == 0)
			return null; // nothing to do
		
		int[][] result;
		if (allParams.size() > 1){
			int[] choices = new int[allParams.size()];
			for (int i = 0; i < choices.length; i++) {
				choices[i] = allParams.get(i).clzs.size();
			}
			result = genPairwiseCombinations(choices);
		} else {
			// only one parameter
			result = new int[allParams.get(0).clzs.size()][1];
			for (int i = 0; i < allParams.get(0).clzs.size(); i++){
				result[i][0] = i;
			}
			
		}
		
		List<Request> newRequests = new ArrayList<Request>();
		
		String urlPrefix = basedURL;
		if (urlPrefix.endsWith("/"))
			urlPrefix = urlPrefix.substring(0, urlPrefix.lastIndexOf("/"));
		
		try {
			
			// process results to produce requests
			for (int i = 0; i < result.length; i++){
				Request request = new Request();
				request.setOriginalSource(Request.REQUEST_SOURCE_COMBIGEN);
				request.setUrl(new URL(urlPrefix + page.getUrlPath()));
				
				for (int j = 0; j < result[i].length; j++){
					ParamInfo pInfo = allParams.get(j);
					if (pInfo.source == Request.PARAM_SOURCE_USER){
						Object paramSpec = pInfo.clzs.get(result[i][j]);
						final String value = generateValue(paramSpec);
						request.addParam(new BurpParameter(pInfo.name, value, pInfo.type));
					} else {
						request.addParam(new BurpParameter(pInfo.name, "to-gen-at-runtime", pInfo.type), Request.PARAM_SOURCE_SERVER);
					}
				}
				
				boolean isPOST = false;
				for (IParameter param : request.getParameters()){
					if (param.getType() == IParameter.PARAM_BODY 
							|| param.getType() == IParameter.PARAM_JSON
							|| param.getType() == IParameter.PARAM_XML
							|| param.getType() == IParameter.PARAM_XML_ATTR
							|| param.getType() == IParameter.PARAM_MULTIPART_ATTR){
						isPOST = true;
					}
				}
				
				if (isPOST)
					request.setMethod("POST");
				else 
					request.setMethod("GET");
				
				newRequests.add(request);
			}
			
			return newRequests;
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
	}
	
	
	/**
	 * Generate concrete value
	 * @param paramSpec
	 * @return
	 */
	private String generateValue(Object paramSpec) {
		if (paramSpec instanceof ComplexDataSpecType) {
			ComplexDataSpecType dataClz = (ComplexDataSpecType)paramSpec;
			IDataGenerator dataGenerator = DataGeneratorFactory.createDataGenerator(dataClz);
			
			if (dataGenerator != null)
				return dataGenerator.generate(dataClz);
			
		} else if (paramSpec instanceof JAXBElement) {
			JAXBElement tmp = (JAXBElement) paramSpec;
			String facetType = tmp.getName().getLocalPart();
			if (facetType.equals("enumeration")){
				Facet facet = (Facet) tmp.getValue();
				return facet.getValue();
			}
		}
		
		return ""; // empty by default
	}


	/**
	 * Invoke Allpairs class to generate pairwise combinatins 
	 * @param choices
	 * @return
	 */
	private int[][] genPairwiseCombinations(int choices[]){
		int[][] result;
		
		AllPairs ap = new AllPairs(choices, SEED, SHOULD_SHUFFLE);
		int bestSofar = Integer.MAX_VALUE;
		int improvementCounter = MAX_TRY_FOR_IMPROVEMENT; // use to stop when no
															// improvement is
															// observed
		for (int go = 0;; go++) {
			switch (go % 2) {
			// Want to do the prime-based generation first as it may
			// be pretty if shuffling is turned off
			case 0:
				result = ap.generateViaPrime(false);
				break;
			case 1:
				result = ap.generateGreedy();
				break;
			default:
				throw new IllegalStateException("PairwiseGenerator: Bad case");
			}

			if (ap.minCount(result) < 1) {
				throw new IllegalStateException(
						"PairwiseGenerator: Generated bad result");
			}
			if (result.length < bestSofar) {
				bestSofar = result.length;
				improvementCounter = MAX_TRY_FOR_IMPROVEMENT; // reset
			} else if (result.length >= bestSofar) {
				improvementCounter--;
			}
			if (((MAX_GOES > 0) && (go >= MAX_GOES))
					|| (improvementCounter == 0)) {
				break;
			}
		}
		
		return result;
	}


	/**
	 * Extract information about the parameters and their classifications from a
	 * tree
	 * 
	 * @param cteTree
	 * @return
	 */
	protected List<ParamInfo> extractCTEInfo(Page page) {
		List<ParamInfo> retList = new ArrayList<PairWiseGenerator.ParamInfo>();

		for (Xinput input : page.getXinput()){
			
			// Skip these types of inputs 
			if (input.getType() != null 
					&& input.getType().equals(InputType.PARAM_COOKIE))
				continue;
			
			if (input.getSource() != null 
					&& input.getSource().equals(SourceType.SERVER)){
				ParamInfo pInfo = new ParamInfo();
				pInfo.name = input.getName();
				pInfo.source = Request.PARAM_SOURCE_SERVER;
				pInfo.type = IParameter.PARAM_BODY;
				pInfo.clzs.add(new String("to-get-at-runtime"));
				
				retList.add(pInfo);
				continue;
			}
			
			
			// populate the list of atomic param
			List<AtomicParam> params = new ArrayList<AtomicParam>();
			params.addAll(input.getAtomicParam());
			
			if (input.getAtomicParamRef().size() > 0){
				for (AtomicParamRef ref : input.getAtomicParamRef()){
					try {
						params.add((AtomicParam) ref.getParamRef());
					} catch (ClassCastException e) {
						// ignore this ref
						e.printStackTrace();
					}
					
				}
			}
			
			ParamInfo pInfo = new ParamInfo();
			pInfo.name = input.getName();
			pInfo.source = Request.PARAM_SOURCE_USER;
			pInfo.type = getType(input);
			for (AtomicParam p : params){
				for (ComplexDataSpecType dataClz : p.getDataClz()){
					if (isEnumeration(dataClz)){
						for (Object o : dataClz.getFacets()){
							pInfo.clzs.add(o);
						}
					} else {
						pInfo.clzs.add(dataClz);
					}
				}
			}
			retList.add(pInfo);
		}
		
		return retList;
	}
	
	/**
	 * get a bupsuite type of an input
	 */
	private byte getType(Xinput input) {
		InputType t = input.getType();
		
		if (t == InputType.PARAM_COOKIE)
			return IParameter.PARAM_COOKIE;
		else if (t == InputType.PARAM_JSON)
			return IParameter.PARAM_JSON;
		else if (t == InputType.PARAM_MULTIPART_ATTR)
			return IParameter.PARAM_MULTIPART_ATTR;
		else if (t == InputType.PARAM_URL)
			return IParameter.PARAM_URL;
		else if (t == InputType.PARAM_XML)
			return IParameter.PARAM_XML;
		else if (t == InputType.PARAM_XML_ATTR)
			return IParameter.PARAM_XML_ATTR;
		else 
			return IParameter.PARAM_BODY;
	}


	/**
	 * Check if data class is an enumeration
	 * @param dataClz
	 * @return
	 */
	private boolean isEnumeration(ComplexDataSpecType dataClz) {
		List<Object> facets = dataClz.getFacets();
		for (Object o : facets) {
			if (o instanceof JAXBElement) {
				JAXBElement tmp = (JAXBElement) o;
				String facetType = tmp.getName().getLocalPart();
				if (facetType.equals("enumeration")){
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Class to represent a parameter
	 * 
	 * @author cdnguyen
	 * 
	 */
	protected class ParamInfo {
		protected String name;
		protected byte type;
		protected byte source; // Request.PARAM_SOURCE_USER or PARAM_SOURCE_SERVER
		
		protected List<Object> clzs = new ArrayList<Object>();
	}
	
}
