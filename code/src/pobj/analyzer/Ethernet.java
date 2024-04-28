package pobj.analyzer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Ethernet {
	
	private char[] source;
	private char[] destination;
	private char[] type;
	
	
	public Ethernet() {
		
		this.destination = new char[12];
		this.source = new char[12];
		this.type = new char[4];	
	}

	public void setSource(char[] source) {
		this.source = source;
	}

	public void setDestination(char[] destination) {
		this.destination = destination;
	}

	public void setType(char[] type) throws AnalyzerException{
		if (!toString(type).equals("0800")) throw new AnalyzerException();
		this.type = type;
	}
	
	public String getSource() {
		return toStringMAC(this.source);
	}

	public String getDestination() {
		return toStringMAC(destination);
	}

	public String getType() {
		return toString(type);
	}

	public String toStringMAC(char[] tab) {
		StringBuilder str = new StringBuilder();
		
		for (int i = 0; i<tab.length; i++) {
			str.append(Character.toString(tab[i]));
			if (i+1 < tab.length && i%2 != 0) {
				str.append(":"); 
			}
			
		}
		return str.toString();
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
		
		str.append("Dest: "+this.getDestination()+"\n");
		str.append("Src: "+this.getSource()+"\n");
		str.append("Type: IPV4 "+"("+this.getType()+")"+"\n");
		
		return str.toString();
	}


}
