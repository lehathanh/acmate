package org.svv.acmate.gui.handlers;

import java.awt.Component;
import java.io.File;

import org.svv.acmate.gui.IMainController;
import org.svv.acmate.model.TargetAppModel;
import org.svv.acmate.model.config.Configuration;
import org.svv.acmate.model.filters.Filters;
import org.svv.acmate.utils.FileUtil;
import org.svv.acmate.utils.JAXBUtil;

public class WorkingDirChangedHandler extends AbstractModelEventHandler {

	public WorkingDirChangedHandler(IMainController controller,
			TargetAppModel model, Component parent) {
		super(controller, model, parent);
	}
	

	@Override
	public void handle() {
		if (model.getWorkingDir() != null){
			String configFilePath = model.getWorkingDir() + File.separator + "config.xml";
			String filterFilePath = model.getWorkingDir() + File.separator + "filters.xml";
			
			if (FileUtil.isFileExist(configFilePath)){
				Configuration config = JAXBUtil.loadConfig(configFilePath);
				if (config != null){
					model.setConfigModel(config);
				}
			}

			if (FileUtil.isFileExist(filterFilePath)){
				Filters filters = JAXBUtil.loadFilters(filterFilePath);
				if (filters != null){
					model.setFilterModel(filters);
				}
			}
		}

	}

}
