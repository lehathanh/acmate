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
package org.svv.miner.logdata;

import java.util.ArrayList;
import java.util.List;

import com.stromberglabs.cluster.UniPoint;

public abstract class LogData {
	public static final String DATA_TYPE_INT = "int";
	public static final String DATA_TYPE_FLOAT = "float";
	public static final String DATA_TYPE_STRING = "string";
	public static final String[] ALL_DATA_TYPES = {DATA_TYPE_STRING, DATA_TYPE_INT, DATA_TYPE_FLOAT};
	
	public static final int MIN_CLUSTERING_SIZE = 10;
	
	
	@SuppressWarnings("rawtypes")
	List entries;
	String dataType;
	
	@SuppressWarnings("unchecked")
	public <T> List<T> getEntries(Class<T> type) {
		 List<T> result = new ArrayList<T>();
		 for(Object e : entries) {
			if (type.isAssignableFrom(e.getClass())) {
				result.add((T)e);
			}
		 }
		 return result;
	}

	
	@SuppressWarnings("rawtypes")
	public List getEntries() {
		return entries;
	}


	@SuppressWarnings("rawtypes")
	public LogData() {
		entries = new ArrayList();
	}
	
	/**
	 * Should apply clustering or not
	 * @return
	 */
	public boolean shouldBeClustered(){
		if (entries.size() > MIN_CLUSTERING_SIZE 
				&& !dataType.equals(DATA_TYPE_STRING)){
			return true;
		} else {
			return false;
		}
	}
	
	public boolean shouldBeEnumerated(){
		if (entries.size() <= MIN_CLUSTERING_SIZE)
			return true;
		return false;
	}
	
	public boolean shouldUseStringBoundary(){
		if (entries.size() >= MIN_CLUSTERING_SIZE 
				&& dataType.equals(DATA_TYPE_STRING))
			return true;
		return false;		
	}
	
	public abstract void add(String value);

	public String getDataType() {
		return dataType;
	}

	public String format(Object value){
		if (dataType.equals(DATA_TYPE_STRING))
			return value.toString();
		if (dataType.equals(DATA_TYPE_INT) && value instanceof UniPoint){
			int intVal = (int)((UniPoint) value).getValue(); 
			return String.valueOf(intVal); 
		}
		if (dataType.equals(DATA_TYPE_FLOAT) && value instanceof UniPoint){
			int intVal = (int)((UniPoint) value).getValue(); 
			return String.valueOf(intVal); 
		} 
		
		return "";
	}
	
}
