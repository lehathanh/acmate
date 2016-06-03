package org.svv.miner;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;

import org.apache.commons.lang3.StringEscapeUtils;
import org.svv.acmate.burpsuite.SiteMap;
import org.svv.acmate.model.Request;
import org.svv.acmate.model.TargetAppModel;
import org.svv.acmate.utils.JAXBUtil;
import org.svv.miner.logdata.LogData;
import org.svv.miner.logdata.NumericData;
import org.svv.miner.logdata.StringData;
import org.svv.xinput.*;

import burp.IParameter;

import com.stromberglabs.cluster.Cluster;
import com.stromberglabs.cluster.ClusterUtils;
import com.stromberglabs.cluster.KClusterer;
import com.stromberglabs.cluster.KMeansClusterer;
import com.stromberglabs.cluster.UniPoint;


public class XinputMiner {
	private static final int  MIN_CLASS_NUMBER = 2;
	private static final int  MAX_CLASS_NUMBER = 4;
	
	private static int xinputCounter = 0;

	
	public boolean mine(SiteMap siteMap, TargetAppModel model, String outputXML) {
		DomainInputs domainInput = mine(siteMap, model);
		if (domainInput != null) {
			
			JAXBUtil.saveDomainInputs(domainInput, outputXML);
			return true;
		} else {
			return false;
		}

	}
	
	/**
	 * Mine domain inputs from a siteMap
	 * @param siteMap, must be not null
	 * @return
	 */
	private DomainInputs mine(SiteMap siteMap, TargetAppModel model){
		if (siteMap == null || siteMap.getPathRequestsMap().isEmpty())
			return null;
		
		DomainInputs domainInputs = new DomainInputs();
		Head head = new Head();
		head.setDataSource("BurpSuite SiteMap");
		head.setStartURL(model.getStartURL());
		domainInputs.setHead(head);
		
		int pageCount = 1;
		for (String pagePath : siteMap.getPathRequestsMap().keySet()){
			Page page = new Page();
			page.setUrlPath(pagePath);
			page.setId("PID_" + String.valueOf(pageCount));
			page.setName("Page_" + String.valueOf(pageCount));
			pageCount = pageCount + 1;
			
			List<Xinput> xinputs = mineXinput(siteMap.getPathRequestsMap().get(pagePath));
			if (xinputs != null){
				page.getXinput().addAll(xinputs);
				domainInputs.getPage().add(page);
			}
		}
		
		return domainInputs;
	}

	private List<Xinput> mineXinput(List<Request> listRequest) {
		// populate parameters and their values
		Map<String, LogData> paramDataMap = new HashMap<String, LogData>();
		Map<String, InputType> paramTypeMap = new HashMap<String, InputType>();
		
		List<Xinput> returnList = new ArrayList<Xinput>();
		
		// populate the map
		for (Request request : listRequest){
			
			// dont consider combi-generated requests
			if (request.getOriginalSource().equals(Request.REQUEST_SOURCE_COMBIGEN))
				continue;
			
			for (IParameter p : request.getParameters()){
				if (!paramDataMap.keySet().contains(p.getName())){
					paramDataMap.put(p.getName(), new StringData());
				}
				
				LogData data = paramDataMap.get(p.getName());
				data.add(p.getValue());
				
				if (!paramTypeMap.keySet().contains(p.getName())){
					InputType iType;
					if (IParameter.PARAM_URL == p.getType()){
						iType = InputType.PARAM_URL;
					} else if (IParameter.PARAM_COOKIE == p.getType()){
						iType = InputType.PARAM_COOKIE;
					} else if (IParameter.PARAM_JSON == p.getType()){
						iType = InputType.PARAM_JSON;
					} else if (IParameter.PARAM_MULTIPART_ATTR == p.getType()){
						iType = InputType.PARAM_MULTIPART_ATTR;
					} else if (IParameter.PARAM_XML == p.getType()){
						iType = InputType.PARAM_XML;
					} else if (IParameter.PARAM_XML_ATTR == p.getType()){
						iType = InputType.PARAM_XML_ATTR;
					} else {
						iType = InputType.PARAM_BODY;
					}
					paramTypeMap.put(p.getName(), iType);
				}
			}
		}
		
		if (paramDataMap.size() == 0){
			paramDataMap.clear();
			return null;
		}
		
		ObjectFactory factory = new ObjectFactory();
		
		for (String param : paramDataMap.keySet()){
			InputType iType = paramTypeMap.get(param);
			
			if (iType.equals(InputType.PARAM_COOKIE))
				continue; // do nothing with cookie 
			
			Xinput input = new Xinput();
			input.setId("XID_" + String.valueOf(xinputCounter++));
			input.setName(StringEscapeUtils.escapeXml10(param));
			
			if (iType != null)
				input.setType(iType);
			else 
				input.setType(InputType.PARAM_UNKNOWN);
			
			// by default all inputs are user inputs
			input.setSource(SourceType.USER);
			
			StringData tmp = (StringData) paramDataMap.get(param);
			LogData data = tmp;
			if (NumericData.isInteger(tmp)){
				// convert to numeric
				data = new NumericData(tmp, LogData.DATA_TYPE_INT);
			} else if (NumericData.isNumeric(tmp)){
				data = new NumericData(tmp, LogData.DATA_TYPE_FLOAT);
			}
			
			AtomicParam atoParam = new AtomicParam();
			input.getAtomicParam().add(atoParam);
			
			if (data.getEntries().size() > 0){
				
				if (data.shouldBeEnumerated()){
					ComplexDataSpecType clz1 = new ComplexDataSpecType();
					clz1.setName(param + "_mined_clz");
					clz1.setBase(new QName("http://acmate.svv.org/xinput", data.getDataType()));
					
					for (Object entry : data.getEntries()){
						NoFixedFacet enumvalue = new NoFixedFacet();
						enumvalue.setValue(data.format(entry));
						clz1.getFacets().add(factory.createEnumeration(enumvalue));
					}
					
					atoParam.getDataClz().add(clz1);
				} else if (data.shouldUseStringBoundary()){
					int maxLen = ((StringData)data ).getMaxLength();
					int minLen = ((StringData)data ).getMinLength();
					
					ComplexDataSpecType clz1 = new ComplexDataSpecType();
					clz1.setName(param + "_mined_clz");
					clz1.setBase(new QName("http://acmate.svv.org/xinput", "string"));
					
					NumFacet minEnumvalue = new NumFacet();
					minEnumvalue.setValue(String.valueOf(minLen));
					clz1.getFacets().add(factory.createMinLength(minEnumvalue));

					NumFacet maxEnumvalue = new NumFacet();
					maxEnumvalue.setValue(String.valueOf(maxLen));
					
					clz1.getFacets().add(factory.createMaxLength(maxEnumvalue));
					
					atoParam.getDataClz().add(clz1);
					
				} else if (data.shouldBeClustered()){
					
					List<UniPoint> allPoints = data.getEntries(UniPoint.class);
					
					int size = (int) Math.sqrt(allPoints.size() / 2.0);
					
					// Consider only 2 -> 4 classes 
					if (size < MIN_CLASS_NUMBER) size = MIN_CLASS_NUMBER;
					if (size > MAX_CLASS_NUMBER) size = MAX_CLASS_NUMBER;
					
					// Do clustering
					KClusterer clusterer = new KMeansClusterer();
					Cluster[] clusters = clusterer.cluster(allPoints,size);
					
					int clzCounter = 1;
					for ( Cluster c : clusters ){
						String clzName = param + "_mined_clz_" + String.valueOf(clzCounter++);
						
						ComplexDataSpecType clz = new ComplexDataSpecType();
						clz.setName(clzName);
						clz.setBase(new QName("http://acmate.svv.org/xinput", data.getDataType()));
						
						Facet minEnumvalue = new Facet();
						minEnumvalue.setValue(data.format(ClusterUtils.getMin(c)));
						clz.getFacets().add(factory.createMinInclusive(minEnumvalue));

						Facet maxEnumvalue = new Facet();
						maxEnumvalue.setValue(data.format(ClusterUtils.getMax(c)));
						clz.getFacets().add(factory.createMaxInclusive(maxEnumvalue));
						
						atoParam.getDataClz().add(clz);
						
					}
				}
				
			} else {
				ComplexDataSpecType clz1 = generateDefaultEnum(param);
				atoParam.getDataClz().add(clz1);
			}
			
			
			returnList.add(input);
			
		}
	
		paramDataMap.clear();
		return returnList;
	}


	/**
	 * Generate a default input, user has to specify manually. This method will create a template any way 
	 * so that the user can start quickly.
	 * 
	 * @param eventName
	 * @return
	 */
	private ComplexDataSpecType generateDefaultEnum(String eventName) {
		ComplexDataSpecType clz1 = new ComplexDataSpecType();
		clz1.setName(eventName + "_default_clz");
		clz1.setBase(new QName("http://acmate.svv.org/xinput", "string"));
		
		NoFixedFacet enumvalue = new NoFixedFacet();
		enumvalue.setValue("to-be-defined");
		QName qname = new QName("http://acmate.svv.org/xinput", "enumeration");
		JAXBElement<NoFixedFacet> enum1 = new JAXBElement<NoFixedFacet>(qname, NoFixedFacet.class, enumvalue);
		clz1.getFacets().add(enum1);
		
		return clz1;
	}


}
