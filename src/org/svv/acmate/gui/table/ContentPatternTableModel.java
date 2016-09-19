package org.svv.acmate.gui.table;

import java.io.Serializable;
import java.util.List;
import java.util.Vector;

import javax.swing.table.AbstractTableModel;

import org.svv.acmate.model.filters.ContentPattern;

public class ContentPatternTableModel extends AbstractTableModel implements Serializable, ITableSelection  {
	/**
	 * 
	 */
	private static final long serialVersionUID = -7853912672775812717L;
	
	
	protected List<ContentPattern> data;
	protected Vector<String> columnIdentifiers;

	/**
	 * Constructor
	 * @param model
	 */
	public ContentPatternTableModel(List<ContentPattern> model) {
		this.data = model;
		
		columnIdentifiers = new Vector<String>();
		
		columnIdentifiers.add("Content");
		columnIdentifiers.add("Matched");
	}
	
	
	@Override
	public String getColumnName(int column) {
		return columnIdentifiers.get(column);
	}



	@Override
	public int getRowCount() {
		return data.size();
	}

	@Override
	public int getColumnCount() {
		return columnIdentifiers.size();
	}


	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		ContentPattern v = data.get(rowIndex);
		if (columnIndex == 0)
			return v.getValue();
		else if (columnIndex == 1){
			return v.isMatched();
		}
		return "";
	}
	
	


	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return true;
	}


	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		ContentPattern v = data.get(rowIndex);
		if (columnIndex == 1){
			v.setMatched((Boolean) aValue); 
			} 
		else {
			v.setValue((String) aValue);
		}
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		if (columnIndex == 0)
			return String.class;
		else 
			return Boolean.class;
	}


	@Override
	public void toggleSelection() {
		fireTableDataChanged();
	}

	/**
	 * Add a new content pattern
	 * @param content pattern
	 */
	public void addPattern(ContentPattern pattern){
		this.data.add(pattern);
		fireTableDataChanged();
	}
	
	/**
	 * Delete a content pattern
	 * @param rowIndex
	 */
	public void deletePattern(int rowIndex){
		this.data.remove(rowIndex);
		fireTableDataChanged();
	}
	
	/**
	 * get a particular content pattern
	 * @param rowIndex
	 * @return
	 */
	public ContentPattern getRow(int rowIndex) {
		return data.get(rowIndex);
	}
	
	public List<ContentPattern> getContentPatterns(){
		return this.data;
	}

}
