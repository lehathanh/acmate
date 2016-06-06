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

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import javax.swing.table.AbstractTableModel;

import org.svv.acmate.executor.ISessionListener;
import org.svv.acmate.executor.Session;

public class SessionTableModel extends AbstractTableModel implements ISessionListener {
	
	protected List<Session> data;
	protected Map<Session, Integer> loadData;
	protected Map<Session, Integer> progressData;
	
	protected Vector<String> columnIdentifiers;
	
	public SessionTableModel(List<Session> sessions) {
		this.data = sessions;
		
		loadData = new HashMap<Session, Integer>();
		progressData = new HashMap<Session, Integer>();
		
		for (Session s: sessions){
			s.setListener(this);
		}
		
		columnIdentifiers = new Vector<String>();
		columnIdentifiers.add("Session");
		columnIdentifiers.add("Progress");
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
		Session s = data.get(rowIndex);
		if (columnIndex == 0) {
			return s.getCurrentUser().getUsername();
		} else if (columnIndex == 1){
			Integer pro = progressData.get(s);
			Integer load = loadData.get(s);
			if (pro != null && load != null)
				return pro.toString() + " / " + load.toString();
		}
		return "";
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		super.setValueAt(aValue, rowIndex, columnIndex);
		
		if (columnIndex == 1){
			this.fireTableCellUpdated(rowIndex, columnIndex);
		}
	}

	@Override
	public void sessionStart(Session s, int load) {
		loadData.put(s, load);
	}

	@Override
	public void sessionDone(Session s) {
		Integer val = loadData.get(s);
		if (val != null)
			progressData.put(s, val); // 100%
		
		fireTableDataChanged();
	}

	@Override
	public void sessionProgress(Session s, int complete) {
//		Integer val = progressData.get(s);
//		if (val != null)
//			val = complete;
//		else 
		progressData.put(s, complete);
		
		fireTableDataChanged();
	}
	
	public void addSession(Session s){
		data.add(s);
		s.setListener(this);
	}
	
}
