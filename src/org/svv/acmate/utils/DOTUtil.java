package org.svv.acmate.utils;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang3.StringEscapeUtils;
import org.svv.acmate.model.Request;
import org.svv.acmate.model.config.PageExtToExclude;

import burp.IParameter;

public class DOTUtil {
	
	private static final String DOT_PROC = "/usr/local/bin/dot";
	
	/**
	 * Export sitemap to a DOT file
	 * @param pathRequestsMap 
	 * 
	 * @param filepath
	 */
	public void export2DOT(String outputFilePath, Map<String, List<Request>> pathRequestsMap, List<PageExtToExclude> exclusionList) {
		if (pathRequestsMap.size() > 0) {
			try {
				FileOutputStream file = new FileOutputStream(outputFilePath);
				PrintStream output = new PrintStream(file);

				output.println("digraph FSM {");
				output.println("edge [color=red];");
				output.println("node [shape=box];");
				
				// printout nodes
				int i = 0;
				for (String key : pathRequestsMap.keySet()){
					
					if (ExtUtil.shouldInclude(key, exclusionList))
						output.println(escape(key) + " [label=\"" + getDOTLabel(key, pathRequestsMap.get(key))  + "\"];");
				}
				
				for (String current : pathRequestsMap.keySet()){
					
					if (ExtUtil.shouldInclude(current, exclusionList)){
						List<Request> currentRequests = pathRequestsMap.get(current);
						
						for (String past : pathRequestsMap.keySet()){
							if (ExtUtil.shouldInclude(past, exclusionList)){
								List<Request> pastRequests = pathRequestsMap.get(past);
								
								if (isPredecesor(pastRequests, currentRequests)){
									output.println(escape(past) + " -> " + escape(current) + ";");
								}
							}
							
						}
					}
				}
				
				output.println("}");
				output.flush();
				output.close();
				
				// try to convert DOT to PDF
				try {
					String pdfFile = outputFilePath.replace(".dot", ".pdf");
					ProcessBuilder pBuilder = new ProcessBuilder(DOT_PROC, "-Tpdf", outputFilePath, "-o", pdfFile);
					pBuilder.start();
					
//		            Process p = Runtime.getRuntime().exec();
		        }
		        catch(IOException e1) {e1.printStackTrace();}

			} catch (IOException e) {
				e.printStackTrace();
			}

		}
	}
	
	
	
	
	
	



	/**
	 * Escape special characters for DOT node id
	 * @param urlPath
	 * @return
	 */
	private String escape(String urlPath){
		String tmp = urlPath.replaceAll("/", "_s_");
		tmp = tmp.replaceAll("\\.", "_dot_");
		tmp = tmp.replaceAll("-", "_");
		tmp = tmp.replaceAll("\\?", "_");
		tmp = tmp.replaceAll(":", "_");
		tmp = tmp.replaceAll("=", "_");
		tmp = tmp.replaceAll("@", "_");
		tmp = tmp.replaceAll(",", "_");
		tmp = tmp.replaceAll("&", "_");
		
		return tmp;
	}
	

	/**
	 * Check if any of the past requests is a predecessor of a current request.
	 * @param pastRequests
	 * @param currentRequests
	 * @return
	 */
	private boolean isPredecesor(List<Request> pastRequests,
			List<Request> currentRequests) {
		for (Request current : currentRequests){
			for (Request past: pastRequests){
				if (current.getPredecesors().contains(past)){
					return true;
				}
			}
		}
		
		return false;
	}

	/**
	 * Build a DOT lable from all parameters
	 * @param key
	 * @param list
	 * @return
	 */
	private String getDOTLabel(String key, List<Request> list) {
		StringBuilder builder = new StringBuilder();
		builder.append(StringEscapeUtils.escapeHtml4(key));
		List<String> uniqueStrings = new ArrayList<String>();
		for (Request r : list){
			for (IParameter kv : r.getParameters()){
				if (!uniqueStrings.contains(kv.getName())){
					uniqueStrings.add(kv.getName());
					builder.append("\\l: " + kv.getName());
				}
			}
		}
		builder.append("\\l");
		uniqueStrings.clear();
		return builder.toString();
	}
}
