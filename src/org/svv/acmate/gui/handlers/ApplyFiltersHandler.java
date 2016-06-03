package org.svv.acmate.gui.handlers;

import java.awt.Component;
import java.awt.event.ComponentEvent;
import java.awt.event.ComponentListener;

import javax.swing.JOptionPane;

import org.svv.acmate.burpsuite.SiteMap;
import org.svv.acmate.gui.IMainController;
import org.svv.acmate.gui.SiteMapProgressFrame;
import org.svv.acmate.model.TargetAppModel;

public class ApplyFiltersHandler extends AbstractSiteMapEventHandler {

	public ApplyFiltersHandler(IMainController controller, TargetAppModel model,
			SiteMap siteMap, Component parent) {
		super(controller, model, siteMap, parent);
	}
	

	@Override
	public void handle() {
		if (model.getStartURL() == null){
			JOptionPane.showMessageDialog(parent, "Please set a start URL from BurpSuite's Target > Site map!");
			return;
		}
		
		if (JOptionPane.showConfirmDialog(parent,
				"Start applying the defined filters?", 
				"Apply filters",
				JOptionPane.YES_NO_OPTION) == JOptionPane.OK_OPTION){
			
//			if (!siteMap.isUpdated()){
//				siteMap.populate(model.getRootRR());
//			}
//			
			SiteMapProgressFrame loadingFrame = new SiteMapProgressFrame(siteMap);
			loadingFrame.addComponentListener(new ComponentListener() {
				
				@Override
				public void componentShown(ComponentEvent e) {
					siteMap.colorBurpsuiteRecord(model.getFilterModel());
				}
				
				@Override
				public void componentResized(ComponentEvent e) {
					// TODO Auto-generated method stub
					
				}
				
				@Override
				public void componentMoved(ComponentEvent e) {
					// TODO Auto-generated method stub
					
				}
				
				@Override
				public void componentHidden(ComponentEvent e) {
					// TODO Auto-generated method stub
					
				}
			});
			loadingFrame.setVisible(true);
		}

	}

}
