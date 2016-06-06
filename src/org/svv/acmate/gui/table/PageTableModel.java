/*******************************************************************************
 * Copyright (c) 2016, SVV Lab, University of Luxembourg
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * 3. Neither the name of acmate nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *******************************************************************************/
package org.svv.acmate.gui.table;

import java.io.Serializable;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import javax.swing.table.AbstractTableModel;

import org.svv.acmate.burpsuite.SiteMap;

public class PageTableModel extends AbstractTableModel implements Serializable, ITableSelection   {
	
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	protected Vector<String> columnIdentifiers;
	List<String> data;
	Map<String, Boolean> selectedPaths;
	
	
	public PageTableModel(SiteMap siteMap) {
		
		this.data = siteMap.getPaths();
		this.selectedPaths = siteMap.getSelectedPaths();
		
		columnIdentifiers = new Vector<String>();
		columnIdentifiers.add("Selected");
		columnIdentifiers.add("URL");
		
		
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
	public String getColumnName(int column) {
		return columnIdentifiers.get(column);
	}
	
	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		String v = data.get(rowIndex);
		if (columnIndex == 1)
			return v;
		else if (columnIndex == 0){
			if (selectedPaths.get(v) == null){
				return new Boolean(false);
			} else {
				return selectedPaths.get(v);
			}
		}
		return "";
	}


	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		if (columnIndex == 0)
			return true;
		
		return false;
	}


	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		String v = data.get(rowIndex);
		if (columnIndex == 0){
			if (selectedPaths.get(v) == null){
				selectedPaths.put(v, new Boolean(true));
			} else {
				if (aValue instanceof Boolean){
					selectedPaths.put(v, (Boolean) aValue);
				}
			}
		}
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		if (columnIndex == 0)
			return Boolean.class;
		else 
			return String.class;
	}

	@Override
	public void toggleSelection() {
		
		int numRow =  getRowCount();
		boolean newVal = true;
		if (numRow > 0){
			String v = data.get(0);
			if (selectedPaths.get(v) != null 
					&& selectedPaths.get(v).booleanValue()){
				newVal = false;
			}
		}
		
		for (int rowIndex = 0; rowIndex < getRowCount(); rowIndex++){
			String v = data.get(rowIndex);
			if (newVal)
				selectedPaths.put(v, new Boolean(true));
			else 
				selectedPaths.put(v, new Boolean(false));
		}
		
		fireTableDataChanged();
	}
	

}
