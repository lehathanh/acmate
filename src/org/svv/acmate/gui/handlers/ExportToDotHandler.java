package org.svv.acmate.gui.handlers;

import java.awt.Component;
import java.io.File;

import javax.swing.JOptionPane;

import org.svv.acmate.burpsuite.SiteMap;
import org.svv.acmate.gui.IMainController;
import org.svv.acmate.model.TargetAppModel;
import org.svv.acmate.utils.DOTUtil;
import org.svv.acmate.utils.FileUtil;

public class ExportToDotHandler extends AbstractSiteMapEventHandler {

	
	

	public ExportToDotHandler(IMainController controller, TargetAppModel model,
			SiteMap siteMap, Component parent) {
		super(controller, model, siteMap, parent);
	}

	@Override
	public void handle() {
		if (model.getWorkingDir() != null){
			String outputFilePath = model.getWorkingDir() + File.separator + "SiteMap.dot";
			
			boolean readyToExport = true;
			if (FileUtil.isFileExist(outputFilePath)){
				if (JOptionPane.showConfirmDialog(parent, 
						"SiteMap.dot file exists in the working folder. Overwrite? ",
						"Exporting to DOT", 
						JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION){
					readyToExport = false;
				}
					
			}
			if (readyToExport){
//				if (!siteMap.isUpdated()){
//					siteMap.populate(model.getRootRR());
//				}
//				
				DOTUtil dotUtil = new DOTUtil();
				dotUtil.export2DOT(outputFilePath, siteMap.getPathRequestsMap(), model.getConfigModel().getPageExtToExclude());
				JOptionPane.showMessageDialog(parent, "ACMate has finished exporting the site map to the working folder!");
			}
		}

	}

}
