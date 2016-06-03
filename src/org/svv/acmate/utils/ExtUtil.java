package org.svv.acmate.utils;

import java.util.List;

import org.svv.acmate.model.config.PageExtToExclude;

public class ExtUtil {
	public static boolean shouldInclude(String key,
			List<PageExtToExclude> exclusionList) {
		if (exclusionList == null) { 
			return true;
		} else {
			for (PageExtToExclude ext : exclusionList){
				if (key.endsWith(ext.getValue())){
					return false;
				}
			}
		}
		
		return true;
	}
}
