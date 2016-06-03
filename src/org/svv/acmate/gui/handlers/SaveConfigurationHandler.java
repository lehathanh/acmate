package org.svv.acmate.gui.handlers;

import java.awt.Component;
import java.io.File;

import javax.swing.JOptionPane;

import org.svv.acmate.gui.IMainController;
import org.svv.acmate.model.TargetAppModel;
import org.svv.acmate.utils.FileUtil;
import org.svv.acmate.utils.JAXBUtil;

public class SaveConfigurationHandler extends AbstractModelEventHandler {

	public SaveConfigurationHandler(IMainController controller,
			TargetAppModel model, Component parent) {
		super(controller, model, parent);
	}


	
	@Override
	public void handle() {
		if (model.getWorkingDir() != null){
			String configFilePath = model.getWorkingDir() + File.separator + "config.xml";
			String filterFilePath = model.getWorkingDir() + File.separator + "filters.xml";
			
			boolean readyToExport = true;
			if (FileUtil.isFileExist(configFilePath)){
				if (JOptionPane.showConfirmDialog(parent, 
						"config.xml file exists in the working folder. Overwrite? ",
						"Initiate configuration", 
						JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION){
					readyToExport = false;
				}
			}
			
			if (readyToExport)
				JAXBUtil.saveConfig(model.getConfigModel(), configFilePath);
			
			readyToExport = true;
			if (FileUtil.isFileExist(filterFilePath)){
				if (JOptionPane.showConfirmDialog(parent, 
						"filters.xml file exists in the working folder. Overwrite? ",
						"Initiate configuration", 
						JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION){
					readyToExport = false;
				}
			}
			
			if (readyToExport)
				JAXBUtil.saveFilters(model.getFilterModel(), filterFilePath);
		}

	}

}
