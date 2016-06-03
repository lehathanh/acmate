/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.svv.acmate.gui;

import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.ComponentEvent;
import java.awt.event.ComponentListener;

import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;

import org.svv.acmate.burpsuite.SiteMap;
import org.svv.acmate.exception.ExecutorException;
import org.svv.acmate.executor.ACTestExecutor;
import org.svv.acmate.executor.ExecutorFactory;
import org.svv.acmate.executor.IExecutorListener;
import org.svv.acmate.gui.handlers.EventHandlerFactory;
import org.svv.acmate.gui.handlers.IEventHandler;
import org.svv.acmate.model.TargetAppModel;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.ITab;

/**
 *
 * @author cdnguyen, hathanh.le
 */
public class MainGUI extends javax.swing.JFrame implements ITab, IMainController {
	
	private final IBurpExtenderCallbacks callbacks;
	private final IExtensionHelpers helpers;
	
	private final TargetAppModel model;
	private final SiteMap siteMap;
	
    JTabbedPane mainController;
    JPanel startPanel;
    JPanel acTestingPanel;
//    JPanel acPolicyPanel;
    
    /**
     * Constructor
     * @param callbacks
     */
    public MainGUI(IBurpExtenderCallbacks burpCallbacks){
    	
    	this.callbacks = burpCallbacks;
    	this.helpers = callbacks.getHelpers();
    	
    	callbacks.customizeUiComponent(this);
    	callbacks.addSuiteTab(this);
    	
    	model = new TargetAppModel();
    	siteMap = new SiteMap(callbacks);
    	
        initComponents();
        
        setSize(new Dimension(1024, 900));

    }

    /**
     * Method to initiate GUI components
     */
    private void initComponents() {
        mainController = new javax.swing.JTabbedPane();
        
        startPanel = new StartPanel(model, this);
        acTestingPanel = new ACTestingPanel(model, siteMap, this);
//        acPolicyPanel = new ACPolicyPanel(model, siteMap);
        mainController.addTab("Options", new OptionPanel());
        
        mainController.addTab("Start", startPanel);
        mainController.addTab("AC Testing", acTestingPanel);

        // Frame
        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addComponent(mainController, javax.swing.GroupLayout.PREFERRED_SIZE, 400, Short.MAX_VALUE)
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addComponent(mainController, javax.swing.GroupLayout.PREFERRED_SIZE, 294, Short.MAX_VALUE)
                .addContainerGap())
        );
        
//        setLayout(new FlowLayout(FlowLayout.LEADING, 0, 0));
//        add(mainController);

        mainController.getAccessibleContext().setAccessibleName("Start");
        mainController.getAccessibleContext().setAccessibleDescription("");
                
        // Frame
        pack();
        
    }

	
	@Override
	public String getTabCaption() {
		return "ACMate-lite";
	}

	@Override
	public Component getUiComponent() {
		return this;
	}
	
	
	
	/**
	 * Start AC Mate with an initial selected item from BurpSuite Gui 
	 * @param selectedMessages
	 */
	public void init(IHttpRequestResponse[] selectedMessages) {
		IRequestInfo info = this.helpers.analyzeRequest(selectedMessages[0]);
	    
		model.setStartURL(info.getUrl().toString());
	    model.setRootRR(selectedMessages[0]);
	    
	    // TODO: check whether a new URL is set or not
	    siteMap.setUpdated(false);
	    updateSiteMap();
	}
	
	/**
	 * Handle view events
	 */
	@Override
	public void handleEvent(String eventType) {
		IEventHandler handler = EventHandlerFactory.createHandler(eventType, this, model, siteMap, this);
		if (handler != null)
			handler.handle();
	}


	@Override
	public int handleEvent(String eventType, int option) {
		int ret = 0;
		if (IMainController.ACTESTING_EVENT_STARTTEST.equals(eventType)){
			ACTestExecutor executor = ExecutorFactory.createExecutor(option, model, siteMap, callbacks);
			executor.registerListener((IExecutorListener) acTestingPanel);
			try {
				executor.execute();
			} catch (ExecutorException e) {
				String message = e.getMessage();
				JOptionPane.showMessageDialog(this, message);
				ret = -1;
			}
//			executor.deregisterListener((IExecutorListener) acTestingPanel);
		}
		
		return ret;
	}

	/**
	 * call sitemap to update its states
	 */
	private void updateSiteMap(){
		if (!siteMap.isUpdated()){
			SiteMapProgressFrame loadingFrame = new SiteMapProgressFrame(siteMap);
			loadingFrame.addComponentListener(new ComponentListener() {
				
				@Override
				public void componentShown(ComponentEvent e) {
					siteMap.populate(model.getRootRR());
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
