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
				return v.getContentPattern().getValue();
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
