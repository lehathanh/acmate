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
