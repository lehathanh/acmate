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

import java.util.List;

import org.apache.commons.lang3.StringUtils;

import com.stromberglabs.cluster.UniPoint;

public class NumericData extends LogData {
	
	public NumericData(String dataType) {
		super();
		this.dataType = dataType;
	}
	
	/**
	 * Check if all values in data are numeric
	 * @param data
	 * @return
	 */
	public static boolean isNumeric(StringData data){
		boolean isN = true;
		List<String> values = data.getEntries();
		for (String s : values){
			if (!StringUtils.isNumeric(s)){
				isN = false;
				return isN;
			}
		}
		return isN;
	}
	
	
	public static boolean isInteger(StringData data){
		boolean isInt = true;
		List<String> values = data.getEntries();
		for (String s : values){
			try { 
				int val = Integer.valueOf(s);
			} catch (NumberFormatException e){
				isInt = false;
				return isInt;
			}
		}
		return isInt;
	}
	
		
	public NumericData(StringData data, String dataType) {
		super();
		this.dataType = dataType;
		List<String> values = data.getEntries();
		for (String value : values){
			add(value);
		}
	}
	
//	public float getLowerBoundary(){
//		float min = Float.MAX_VALUE;
//		for (UniPoint p : getEntries(UniPoint.class)){
//			if (p.getValue() < min)
//				min = p.getValue();
//		}
//		return min;
//	}
//
//	public float getUpperBoundary(){
//		float max = Float.MIN_VALUE;
//		for (UniPoint p : getEntries(UniPoint.class)){
//			if (p.getValue() > max)
//				max = p.getValue();
//		}
//		return max;
//	}

	@Override
	public void add(String value) {
		float v = Float.valueOf(value).floatValue();
		UniPoint point = new UniPoint(v);
		if (!getEntries().contains(point))
			getEntries().add(point);
	}
	
}
