package org.svv.acmate.utils;

import java.io.File;

public class FileUtil {
	
	/**
	 * Check if a file exist
	 * @param filePath
	 * @return
	 */
	public static boolean isFileExist(String filePath){
		File f = new File(filePath);
		if (f.exists())
			return true;
		return false;
	}
}
