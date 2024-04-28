package pobj.analyzer;

import java.io.IOException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HTTP {
	
	public ArrayList<String> request;
	private String head_req;

	public HTTP() {
		this.request = new ArrayList<String>();
	}

	public ArrayList<String> getRequest() {
		return request;
	}
	
	public String printRequest() {
		
		StringBuilder str = new StringBuilder();
		for (String s : request) {
			str.append(s);
			str.append("\n");
			
		}
		return str.toString();
	}
	
	public String getHead_req() {
		return head_req;
	}

	public void httpParser(char[] tab) {
		
		String[] res = toString(tab).split("0d0a");
		
		for (String s : res) {
			request.add(s+"0d0a");	
		}
		
		request.add("0d0a");
		
		if (request.get(0).trim().split("20").length == 3) {
			this.head_req = request.get(0).trim();
		}else {
			request = new ArrayList<String>();
		}
		
		
	}
	
	public String toString(char[] tab) {
		StringBuilder str = new StringBuilder();
		
		for (int i = 0; i<tab.length; i++) {
			str.append(Character.toString(tab[i]));
		}
		return str.toString();
	}
	
	public String toString() {
		
		StringBuilder str = new StringBuilder();
		str.append("Head Request: "+Convert.HextoText(this.getHead_req())+"\n");

		return str.toString();
	}

	

}
