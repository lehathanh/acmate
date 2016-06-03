package org.svv.acmate.gui.handlers;

import java.awt.Component;
import java.io.File;

import javax.swing.JOptionPane;

import org.svv.acmate.burpsuite.SiteMap;
import org.svv.acmate.gui.IMainController;
import org.svv.acmate.model.TargetAppModel;
import org.svv.acmate.utils.FileUtil;
import org.svv.miner.XinputMiner;

public class MineDomainInputsHandler extends AbstractSiteMapEventHandler {

	public MineDomainInputsHandler(IMainController controller,
			TargetAppModel model, SiteMap siteMap, Component parent) {
		super(controller, model, siteMap, parent);
	}

	@Override
	public void handle() {
		if (model.getStartURL() == null || model.getWorkingDir() == null){
			JOptionPane.showMessageDialog(parent, "Please set a start URL from BurpSuite and a working dir!");
			return;
		}
		
		
		String outputXinputFile = model.getWorkingDir() + File.separator + "xinput.xml";
		if (FileUtil.isFileExist(outputXinputFile)){
			if (JOptionPane.showConfirmDialog(parent, 
					"Xinput.xml exists in the working folder. Overwrite? ",
					"Exporting xinput", 
					JOptionPane.YES_NO_OPTION) != JOptionPane.YES_OPTION){
				return;
			}
				
		}
		
		if (JOptionPane.showConfirmDialog(parent,
				"Start inferring domain inputs?", 
				"Inferring domain inputs",
				JOptionPane.YES_NO_OPTION) == JOptionPane.OK_OPTION){
			
			if (!siteMap.isUpdated()){
				siteMap.populate(model.getRootRR());
			}
			
			XinputMiner miner = new XinputMiner();
			if (miner.mine(siteMap, model, outputXinputFile)){
				JOptionPane.showMessageDialog(parent, "ACMate has created xinput.xml in the working directory!");
			} else {
				JOptionPane.showMessageDialog(parent, "ACMate has failed to create an xinput file", 
						"XInput Generation", 
						JOptionPane.ERROR_MESSAGE);
			}
		}

	}

}
