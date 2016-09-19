package org.svv.acmate.gui.table;

import java.io.Serializable;
import java.util.List;
import java.util.Vector;

import javax.swing.table.AbstractTableModel;

import org.svv.acmate.model.filters.Filter;


public class FilterTableModel  extends AbstractTableModel implements Serializable   {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -5934186412469177768L;
	
	
	protected List<Filter> data;
	protected Vector<String> columnIdentifiers;
	
	public FilterTableModel(List<Filter> data) {
		this.data = data;
		columnIdentifiers = new Vector<String>();
		
//		columnIdentifiers.add("Name");
		columnIdentifiers.add("URL Pattern");
		columnIdentifiers.add("Method");
		columnIdentifiers.add("Status Code");
		columnIdentifiers.add("Content Pattern");
		columnIdentifiers.add("Permission");
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
	public String getValueAt(int rowIndex, int columnIndex) {
		Filter v = data.get(rowIndex);
		if (columnIndex == 0){
			if (v.getURLPattern() != null)
				return v.getURLPattern().getValue();
			else 
				return "";
		} else if (columnIndex == 1) {
			if (v.getMethodPattern() != null)
				return v.getMethodPattern().getValue();
			else
				return "";
		} else if (columnIndex == 2) {
			if (v.getStatusCodePattern() != null)
				return v.getStatusCodePattern().getValue();
			else
				return "";
		} else if (columnIndex == 3) {
			if (v.getContentPattern() != null){
				return v.getContentPatternString();
			} else 
				return "";
		} else if (columnIndex == 4){
			return v.getPermission();
		}
		return "";
	}

		
	/**
	 * Load filter configuration from a file
	 */
	public void loadFromFile(String filePath){
		
	}
	
	/**
	 * Add a new filter
	 * @param filter
	 */
	public void addFilter(Filter filter){
		this.data.add(filter);
		fireTableDataChanged();
	}
	
	/**
	 * Delete a filter
	 * @param rowIndex
	 */
	public void deleteFilter(int rowIndex){
		this.data.remove(rowIndex);
		fireTableDataChanged();
	}
	
	/**
	 * get a particular filter
	 * @param rowIndex
	 * @return
	 */
	public Filter getRow(int rowIndex) {
		return data.get(rowIndex);
	}
	
	public List<Filter> getFilters(){
		return this.data;
	}
}
