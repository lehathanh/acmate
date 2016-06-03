package org.svv.acmate.utils;

import java.io.FileInputStream;
import java.io.FileWriter;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;

import org.svv.acmate.model.config.Configuration;
import org.svv.acmate.model.filters.Filters;
import org.svv.acmate.model.sessions.Sessions;
import org.svv.xinput.DomainInputs;


public class JAXBUtil {
	
	/**
	 * Save sessions object to xml file
	 * @param sessions
	 * @param filePath
	 */
	public static boolean saveSessions(Sessions sessions, String filePath){
		try{
			JAXBContext jct = JAXBContext.newInstance(org.svv.acmate.model.sessions.ObjectFactory.class.getPackage().getName()
					, org.svv.acmate.model.sessions.ObjectFactory.class.getClassLoader());
			Marshaller m = jct.createMarshaller();
			m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
			m.marshal(sessions, new FileWriter(filePath));
			return true;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
	}
	
	/**
	 * load sessions object from xml file
	 * @param filePath
	 * @return
	 */
	public static Sessions loadSessions(String filePath){
		try{
			JAXBContext jct = JAXBContext.newInstance(org.svv.acmate.model.sessions.ObjectFactory.class.getPackage().getName()
					, org.svv.acmate.model.sessions.ObjectFactory.class.getClassLoader());
			Unmarshaller m = jct.createUnmarshaller();
			return (Sessions)m.unmarshal(new FileInputStream(filePath));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	
	
	
	/**
	 * Save a configuration object to a file
	 * @param configObject
	 * @param filePath
	 * @return 
	 */
	public static void saveConfig(Configuration configObject, String filePath){
		try{
			JAXBContext jct = JAXBContext.newInstance(org.svv.acmate.model.config.ObjectFactory.class.getPackage().getName()
					, org.svv.acmate.model.config.ObjectFactory.class.getClassLoader());
			Marshaller m = jct.createMarshaller();
			m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
			m.marshal(configObject, new FileWriter(filePath));
		} catch (Exception e) {
			e.printStackTrace();
		}		
	}
	
	/**
	 * Load a config file
	 * @param filePath
	 * @return null if jaxb raises an exception, a configuration object otherwise
	 */
	public static Configuration loadConfig(String filePath){
		try{
			JAXBContext jct = JAXBContext.newInstance(org.svv.acmate.model.config.ObjectFactory.class.getPackage().getName()
					, org.svv.acmate.model.config.ObjectFactory.class.getClassLoader());
			Unmarshaller m = jct.createUnmarshaller();
			return (Configuration)m.unmarshal(new FileInputStream(filePath));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;	
	}
	
	
	/**
	 * Save filters to an xml file
	 * 
	 * @param object
	 * @param filePath
	 */
	public static void saveFilters(Filters object, String filePath){
		try{
			JAXBContext jct = JAXBContext.newInstance(org.svv.acmate.model.filters.ObjectFactory.class.getPackage().getName()
					, org.svv.acmate.model.filters.ObjectFactory.class.getClassLoader());
			Marshaller m = jct.createMarshaller();
			m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
			m.marshal(object, new FileWriter(filePath));
		} catch (Exception e) {
			e.printStackTrace();
		}		
	}

	/**
	 * Load filters from an xml files
	 * 
	 * @param filePath
	 * @return
	 */
	public static Filters loadFilters(String filePath){
		try{
			JAXBContext jct = JAXBContext.newInstance(org.svv.acmate.model.filters.ObjectFactory.class.getPackage().getName()
					, org.svv.acmate.model.filters.ObjectFactory.class.getClassLoader());
			Unmarshaller m = jct.createUnmarshaller();
			return (Filters)m.unmarshal(new FileInputStream(filePath));
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;	
	}
	

	/**
	 * Load domain input specification
	 * 
	 * @param fileName
	 * @return
	 */
	public static DomainInputs loadDomainInputs(String fileName) {
		
		try {
//			JAXBContext jct = JAXBContext.newInstance("org.svv.xinput");
			JAXBContext jct = JAXBContext.newInstance(org.svv.xinput.ObjectFactory.class.getPackage().getName()
					, org.svv.xinput.ObjectFactory.class.getClassLoader());
			Unmarshaller um = jct.createUnmarshaller();
			
			DomainInputs ret = (DomainInputs) um.unmarshal(new FileInputStream(fileName));
			return ret;
			// return ret.getValue();
		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Save domain input spec to an XML file
	 * @param object
	 * @param fileName
	 */
	public static void saveDomainInputs(DomainInputs object, String fileName) {
		try {
			JAXBContext jct = JAXBContext.newInstance(org.svv.xinput.ObjectFactory.class.getPackage().getName()
					, org.svv.xinput.ObjectFactory.class.getClassLoader());
			Marshaller m = jct.createMarshaller();
			m.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
			m.setProperty(Marshaller.JAXB_SCHEMA_LOCATION, "");
			m.marshal(object, new FileWriter(fileName));
			// return ret.getValue();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
