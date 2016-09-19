/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.svv.acmate.gui;

import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.swing.JOptionPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;

import org.svv.acmate.gui.table.ContentPatternTableModel;
import org.svv.acmate.model.filters.ContentPattern;
import org.svv.acmate.model.filters.Filter;
import org.svv.acmate.model.filters.MethodPattern;
import org.svv.acmate.model.filters.StatusCodePattern;
import org.svv.acmate.model.filters.URLPattern;


/**
 *
 * @author cdnguyen
 * @update: thanhhale
 * 
 */
public class FilterDialog extends javax.swing.JDialog {
	
	private int selectedOption = JOptionPane.OK_OPTION;
	private Filter filter;
	
	private ContentPatternTableModel contentPatternModel;
	
	public Filter getFilter() {
		return filter;
	}

	public int getSelectedOption() {
		return selectedOption;
	}


	/**
     * Creates new form FilterDialog from a filter object
     */
    public FilterDialog(Filter item) {
    	
        initComponents();
        
        setTitle("Update a filter");
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setModal(true);
        
        this.filter = item;
        bttnAdd.setText("Update");
        
        setValues();

        tblContentPatterns.setModel(contentPatternModel);

		tblContentPatterns.setColumnSelectionAllowed(false);
		tblContentPatterns.getTableHeader().setReorderingAllowed(false);
		
		tblContentPatterns.getColumnModel().getSelectionModel().setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
		tblContentPatterns.getColumnModel().getColumn(0).setResizable(true);
		tblContentPatterns.getColumnModel().getColumn(0).setWidth(355);
		tblContentPatterns.getColumnModel().getColumn(0).setPreferredWidth(355);
		tblContentPatterns.getColumnModel().getColumn(1).setResizable(false);
		tblContentPatterns.getColumnModel().getColumn(1).setWidth(65);
		tblContentPatterns.getColumnModel().getColumn(1).setPreferredWidth(65);
		tblContentPatterns.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        
    }
    
    
    /**
     * Creates new form FilterDialog
     */
    public FilterDialog() {
        initComponents();
        
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setModal(true);
        setTitle("Add a new filter");
        filter = new Filter();
        
        ContentPattern contentPattern = new ContentPattern();
        contentPattern.setValue("");
        contentPattern.setMatched(false);

        List<ContentPattern> contentPatternList = new ArrayList<>();
    	contentPatternList.add(contentPattern);
    	contentPatternModel = new ContentPatternTableModel(contentPatternList);
        tblContentPatterns.setModel(contentPatternModel);
        
        tblContentPatterns.setColumnSelectionAllowed(false);
        tblContentPatterns.getTableHeader().setReorderingAllowed(false);
        
        tblContentPatterns.getColumnModel().getSelectionModel().setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
        tblContentPatterns.getColumnModel().getColumn(0).setResizable(true);
        tblContentPatterns.getColumnModel().getColumn(0).setWidth(355);
        tblContentPatterns.getColumnModel().getColumn(0).setPreferredWidth(355);
        tblContentPatterns.getColumnModel().getColumn(1).setResizable(false);
        tblContentPatterns.getColumnModel().getColumn(1).setWidth(65);
        tblContentPatterns.getColumnModel().getColumn(1).setPreferredWidth(65);
        tblContentPatterns.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
    }
    
    /**
     * Set values to controls
     */
    private void setValues(){
    	
        if(filter.getContentPattern() == null) {
        	ContentPattern contentPattern = new ContentPattern();
        	contentPattern.setValue("");
        	contentPattern.setMatched(false);
        	
        	List<ContentPattern> contentPatternList = new ArrayList<>();
        	contentPatternList.add(contentPattern);
        	contentPatternModel = new ContentPatternTableModel(contentPatternList);
        }
        else {
        	contentPatternModel = new ContentPatternTableModel(filter.getContentPattern());
        }

        if (filter.getContentPattern() != null){
//    		for(ContentPattern contentPattern : filter.getContentPattern()) {
//    			contentPatternModel.addPattern(contentPattern);
//    		}
    	}
    	
    	if (filter.getStatusCodePattern() != null){
    		txtHTTPCodePattern.setText(filter.getStatusCodePattern().getValue());
    		cboxCodeMatched.setSelected(filter.getStatusCodePattern().isMatched());
    	}
    	
    	if (filter.getMethodPattern() != null){
    		txtHttpMethod.setText(filter.getMethodPattern().getValue());
    		cboxMethodMatched.setSelected(filter.getMethodPattern().isMatched());
    	}
    	
    	if (filter.getURLPattern() != null){
    		txtUrlPattern.setText(filter.getURLPattern().getValue());
    		cboxUrlMatched.setSelected(filter.getURLPattern().isMatched());
    	}
    	
        if (Filter.FILTER_PERMISSION_ALLOWED.equals(filter.getPermission()))
        	comboPermission.setSelectedIndex(0);
        else
        	comboPermission.setSelectedIndex(1);
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">                          
    private void initComponents() {

    	jLabel1 = new javax.swing.JLabel();
        txtUrlPattern = new javax.swing.JTextField();
        jLabel2 = new javax.swing.JLabel();
        txtHTTPCodePattern = new javax.swing.JTextField();
        jLabel3 = new javax.swing.JLabel();
        bttnAdd = new javax.swing.JButton();
        jLabel4 = new javax.swing.JLabel();
        txtHttpMethod = new javax.swing.JTextField();
        jLabel5 = new javax.swing.JLabel();
        comboPermission = new javax.swing.JComboBox();
        bttnCancel = new javax.swing.JButton();
        cboxUrlMatched = new javax.swing.JCheckBox();
        cboxMethodMatched = new javax.swing.JCheckBox();
        cboxCodeMatched = new javax.swing.JCheckBox();
        jScrollPane1 = new javax.swing.JScrollPane();
        tblContentPatterns = new javax.swing.JTable();
        bttnAddContentPattern = new javax.swing.JButton();
        bttnDeleteContentPattern = new javax.swing.JButton();
        jLabel6 = new javax.swing.JLabel();

//   Don't use this:     setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setMaximumSize(new java.awt.Dimension(644, 442));
        setMinimumSize(new java.awt.Dimension(644, 442));

        jLabel1.setText("URL Pattern: ");

        jLabel2.setText("HTTP Code Pattern:");

        jLabel3.setText("Content Pattern:");

        bttnAdd.setText("Add");
        bttnAdd.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                bttnAddActionPerformed(evt);
            }
        });

        jLabel4.setText("HTTP Method:");

        jLabel5.setText("Permission:");

        comboPermission.setModel(new javax.swing.DefaultComboBoxModel(new String[] { "Allowed", "Denied" }));
        comboPermission.setToolTipText("");

        bttnCancel.setText("Cancel");
        bttnCancel.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                bttnCancelActionPerformed(evt);
            }
        });

        cboxUrlMatched.setText("Matched");
        cboxUrlMatched.setToolTipText("Uncheck if the pattern should not match");

        cboxMethodMatched.setText("Matched");
        cboxMethodMatched.setToolTipText("Uncheck if the pattern should not match");

        cboxCodeMatched.setText("Matched");
        cboxCodeMatched.setToolTipText("Uncheck if the pattern should not match");

        tblContentPatterns.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        tblContentPatterns.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if (e.getClickCount() == 2){
					// double click
//					updateFilterACtionPerformed();
				}
				
			}
		});
        
        jScrollPane1.setViewportView(tblContentPatterns);

        bttnAddContentPattern.setText("+");
        bttnAddContentPattern.setToolTipText("");
        bttnAddContentPattern.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                bttnAddContentPatternActionPerformed(evt);
            }
        });

        bttnDeleteContentPattern.setText("-");
        bttnDeleteContentPattern.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                bttnDeleteContentPatternActionPerformed(evt);
            }
        });

        jLabel6.setText("Use Java Regular Expression, leave textboxes blank if not applicable");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(layout.createSequentialGroup()
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                        .addComponent(jLabel2)
                                        .addComponent(jLabel1)
                                        .addComponent(jLabel3))
                                    .addComponent(jLabel4, javax.swing.GroupLayout.Alignment.LEADING))
                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(layout.createSequentialGroup()
                                        .addGap(320, 320, 320)
                                        .addComponent(bttnAdd, javax.swing.GroupLayout.PREFERRED_SIZE, 87, javax.swing.GroupLayout.PREFERRED_SIZE)
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(bttnCancel))
                                    .addGroup(layout.createSequentialGroup()
                                        .addGap(18, 18, 18)
                                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                            .addComponent(comboPermission, javax.swing.GroupLayout.PREFERRED_SIZE, 369, javax.swing.GroupLayout.PREFERRED_SIZE)
                                            .addGroup(layout.createSequentialGroup()
                                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                                    .addComponent(txtUrlPattern, javax.swing.GroupLayout.DEFAULT_SIZE, 378, Short.MAX_VALUE)
                                                    .addComponent(txtHttpMethod)
                                                    .addComponent(txtHTTPCodePattern))
                                                .addGap(3, 3, 3)
                                                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                                    .addComponent(cboxUrlMatched)
                                                    .addComponent(cboxMethodMatched)
                                                    .addComponent(cboxCodeMatched)))))))
                            .addComponent(jLabel5)
                            .addComponent(jLabel6))
                        .addGap(0, 0, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(157, 157, 157)
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 435, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                            .addComponent(bttnAddContentPattern, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.PREFERRED_SIZE, 0, Short.MAX_VALUE)
                            .addComponent(bttnDeleteContentPattern, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.PREFERRED_SIZE, 40, javax.swing.GroupLayout.PREFERRED_SIZE))))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel6)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel1)
                    .addComponent(txtUrlPattern, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(cboxUrlMatched))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(txtHttpMethod, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(cboxMethodMatched)
                    .addComponent(jLabel4))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(txtHTTPCodePattern, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(cboxCodeMatched))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel3)
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 181, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(bttnAddContentPattern)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(bttnDeleteContentPattern)))
                .addGap(18, 18, 18)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel5)
                    .addComponent(comboPermission, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(27, 27, 27)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(bttnAdd)
                    .addComponent(bttnCancel))
                .addContainerGap())
        );
        
        pack();
    }// </editor-fold>                        


    private void bttnAddContentPatternActionPerformed(java.awt.event.ActionEvent evt) {
       	ContentPattern contentPattern = new ContentPattern();
    	contentPattern.setValue("");
    	contentPattern.setMatched(false);
    	
    	contentPatternModel.addPattern(contentPattern);
    	
    }                                                     

    private void bttnDeleteContentPatternActionPerformed(java.awt.event.ActionEvent evt) {                                                         
    	int selectedContentPatternIndex = tblContentPatterns.getSelectedRow();
    	if(selectedContentPatternIndex > -1) {
    		
    		if(JOptionPane.showConfirmDialog(this, "Really want to delete the selected pattern?",
    				"Delete content pattern", JOptionPane.YES_NO_OPTION) == JOptionPane.YES_OPTION) {
    			contentPatternModel.deletePattern(selectedContentPatternIndex);
    		}
    	}
    	
    }                                                        

    private void bttnAddActionPerformed(java.awt.event.ActionEvent evt) {   
    	
    	boolean contentMatched;
    	String regx;
    	
//    	contentMatched = cboxContentMatched.isSelected();
//    	regx = txtContentPattern.getText();
//    	if (checkJavaRegx(regx)){
//    		if (filter.getContentPattern() == null){
//    			ContentPattern content = new ContentPattern();
//	    		content.setValue(regx);
//	    		content.setMatched(contentMatched);
//	    		filter.setContentPattern(content);
//    		} else {
//    			filter.getContentPattern().setMatched(contentMatched);
//    			filter.getContentPattern().setValue(regx);
//    		}
//    	}

    	// Method pattern
    	contentMatched = cboxMethodMatched.isSelected();
    	regx = txtHttpMethod.getText();
    	
    	if (checkJavaRegx(regx)){
    		if (filter.getMethodPattern() == null){
    			MethodPattern p = new MethodPattern();
	    		p.setValue(regx);
	    		p.setMatched(contentMatched);
	    		filter.setMethodPattern(p);
    		} else {
    			filter.getMethodPattern().setMatched(contentMatched);
    			filter.getMethodPattern().setValue(regx);
    		}
    	}
        
    	// URL pattern
        contentMatched = cboxUrlMatched.isSelected();
    	regx = txtUrlPattern.getText();
    	
    	if (checkJavaRegx(regx)){
    		if (filter.getURLPattern() == null){
    			URLPattern p = new URLPattern();
	    		p.setValue(regx);
	    		p.setMatched(contentMatched);
	    		filter.setURLPattern(p);
    		} else {
    			filter.getURLPattern().setMatched(contentMatched);
    			filter.getURLPattern().setValue(regx);
    		}
    	}
        
    	// HTTP Code pattern
        contentMatched = cboxCodeMatched.isSelected();
    	regx = txtHTTPCodePattern.getText();
    	
    	if (checkJavaRegx(regx)){
    		if (filter.getStatusCodePattern() == null){
    			StatusCodePattern p = new StatusCodePattern();
	    		p.setValue(regx);
	    		p.setMatched(contentMatched);
	    		filter.setStatusCodePattern(p);
    		} else {
    			filter.getStatusCodePattern().setMatched(contentMatched);
    			filter.getStatusCodePattern().setValue(regx);
    		}
    	}

    	// Content pattern
    	if(contentPatternModel.getContentPatterns() != null) 
    		filter.setContentPattern(contentPatternModel.getContentPatterns());

        // Permission
        if (comboPermission.getSelectedIndex() == 0){
        	filter.setPermission(Filter.FILTER_PERMISSION_ALLOWED);
        } else 
        	filter.setPermission(Filter.FILTER_PERMISSION_DENIED);
        
        selectedOption = JOptionPane.OK_OPTION;
        this.setVisible(false);
    }     
    
    /**
     * 
     * @param regx
     */
    private boolean checkJavaRegx(String regex){
    	
    	if (regex == null || regex.isEmpty())
    		return true;
    	
    	try {
    		Pattern.compile(regex);
    	} catch (PatternSyntaxException e){
    		JOptionPane.showMessageDialog(this, "Pattern: " + regex + " is not an accepted Java Regular Expression!");
    		return false;
    	}
    	
    	return true;
    	
    }

    private void bttnCancelActionPerformed(java.awt.event.ActionEvent evt) {        
    	selectedOption = JOptionPane.CANCEL_OPTION;
    	this.setVisible(false);
    }                                          
   
    // Variables declaration - do not modify                     
    private javax.swing.JButton bttnAdd;
    private javax.swing.JButton bttnAddContentPattern;
    private javax.swing.JButton bttnCancel;
    private javax.swing.JButton bttnDeleteContentPattern;
    private javax.swing.JCheckBox cboxCodeMatched;
    private javax.swing.JCheckBox cboxMethodMatched;
    private javax.swing.JCheckBox cboxUrlMatched;
    private javax.swing.JComboBox comboPermission;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JTable tblContentPatterns;
    private javax.swing.JTextField txtHTTPCodePattern;
    private javax.swing.JTextField txtHttpMethod;
    private javax.swing.JTextField txtUrlPattern;
    // End of variables declaration                   
}
