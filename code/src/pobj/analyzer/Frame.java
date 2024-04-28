package pobj.analyzer;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Frame {
	
	private int id = 0;
	private static int cpt = 0;
	private String frame;
	private int offset;
	
	
	private Ethernet ethernet;
	private IP ip;
	private TCP tcp;
	private HTTP http;
	private ArrayList<String> Err = new ArrayList<String>();
	List<String> hexa = Arrays.asList("0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "a", "b", "c", "d", "e", "f");
	
	
	public Frame(String frame) {
		id = cpt++;

		this.Err = new ArrayList<String>();
		this.frame = frame;
	}
	
	
	public ArrayList<String> analyzer() throws AnalyzerException {
		try { if(verif() == false) { 
			throw new AnalyzerException("Probleme : caracteres non Hexadecimaux détectés");}
		} 
		catch(AnalyzerException ae) { Err.add("Probleme : caracteres non Hexadecimaux détectés"); return Err; };
		try {
		this.ethernet = new Ethernet();
		if (frame.length() < 28) { Err.add("Probleme : Format de trame incorrect "); return Err; }
		
		char[] Destination = new char[12]; frame.getChars(0, 12, Destination, 0); ethernet.setDestination(Destination);
		char[] Source = new char[12]; frame.getChars(12, 24, Source, 0); ethernet.setSource(Source);
		
		char[] Type = new char[4]; frame.getChars(24, 28, Type, 0); try {ethernet.setType(Type);} catch(AnalyzerException ae) { Err.add("Probleme : Type non supporté"); return Err; };
		
		this.ip = new IP();
		char[] Version = new char[1]; frame.getChars(28, 29, Version, 0); try {ip.setVersion(Version);} catch(AnalyzerException ae) { Err.add("Probleme : Version IP non supportée"); return Err; };
		char[] IHL = new char[1]; frame.getChars(29, 30, IHL, 0); ip.setIHL(IHL); 
		char[] TOS = new char[2]; frame.getChars(30, 32, TOS, 0); ip.setTOS(TOS);                
		char[] Total_Length = new char[4]; frame.getChars(32, 36, Total_Length, 0); ip.setTotal_Length(Total_Length);        
		char[] Identification = new char[4]; frame.getChars(36, 40, Identification, 0); ip.setIdentification(Identification);      
		char[] Flags = new char[1]; frame.getChars(40, 41, Flags, 0); ip.setFlags(Flags);               
		char[] Fragment_offset = new char[3]; frame.getChars(41, 44, Fragment_offset, 0); ip.setFragment_offset(Fragment_offset);
		char[] TTL = new char[2]; frame.getChars(44, 46, TTL, 0); ip.setTTL(TTL);                
		char[] Protocol = new char[2]; frame.getChars(46, 48, Protocol, 0); try {ip.setProtocol(Protocol); } catch(AnalyzerException ae) { Err.add("Probleme : Protocol IP non supporté"); return Err; };          
		char[] Header_Checksum = new char[4]; frame.getChars(48, 52, Header_Checksum, 0); ip.setHeader_Checksum(Header_Checksum);     
		char[] Source_Address = new char[8]; frame.getChars(52, 60, Source_Address, 0); ip.setSource_Address(Source_Address);      
		char[] Destination_Address = new char[8]; frame.getChars(60, 68, Destination_Address, 0); ip.setDestination_Address(Destination_Address); 
		char[] OptionsandPadding = optionIP_Parser(); ip.setOptionsandPadding(OptionsandPadding);  
		
		this.tcp = new TCP(ip);
		
		char[] Source_port = new char[4]; frame.getChars(68, 72, Source_port, 0); tcp.setSource_port(Source_port);
		char[] Destination_port = new char[4]; frame.getChars(72, 76, Destination_port, 0); tcp.setDestination_port(Destination_port); 
		char[] Sequence_Number = new char[8]; frame.getChars(76, 84, Sequence_Number, 0); tcp.setSequence_Number(Sequence_Number);
		char[] Acknowledgment_Number = new char[8]; frame.getChars(84, 92, Acknowledgment_Number, 0); tcp.setAcknowledgment_Number(Acknowledgment_Number);
		char[] Data_Offset = new char[1]; frame.getChars(92, 93, Data_Offset, 0); tcp.setData_Offset(Data_Offset);
		char[] Flags_TCP = new char[3]; frame.getChars(93, 96, Flags_TCP, 0); tcp.setFlags(Flags_TCP);                        
		char[] Window = new char[4]; frame.getChars(96, 100, Window, 0); tcp.setWindow(Window);          
		char[] Cheksum = new char[4]; frame.getChars(100, 104, Cheksum, 0); tcp.setCheksum(Cheksum);       
		char[] Urgent_Pointer = new char[4]; frame.getChars(104, 108, Urgent_Pointer, 0); tcp.setUrgent_Pointer(Urgent_Pointer);  
		optionTCP_Parser();

		http = new HTTP();
		if (frame.length() - offset > 0 && (tcp.getSource_port().equals("80") || tcp.getDestination_port().equals("80")) 
				&& (tcp.getACK()[0]=='1' && tcp.getPSH()[0]=='1')) {

			char[] req = new char[frame.length()-offset];
			frame.getChars(offset, frame.length(), req, 0);
			http.httpParser(req);
		}
		
		if (frame.length() - offset == 0 && http.getRequest().size()==0) {
			tcp.verifChecksumTCP();
		}
		
		return Err;
		
		}catch(Exception e) {
			
			Err.add("Probleme : Format de trame incorrect "); return Err;	
		}
		
		
	
	}

	public char[] optionIP_Parser() {
		if (Integer.parseInt(Convert.HextoDec(ip.getIHL())) == 5) {
			this.offset = 108;
			return new char[0];
		}
		
		char[] opt = new char[(Integer.parseInt(Convert.HextoDec(ip.getIHL()))-5)*8];
		this.offset = 108+(Integer.parseInt(Convert.HextoDec(ip.getIHL()))-5)*8;
		frame.getChars(108, offset, opt, 0);
		
		return opt;
	}
	
	public void optionTCP_Parser() {
		
		if (Integer.parseInt(Convert.HextoDec(tcp.getData_Offset())) == 5) {
			tcp.AddOptions("");
			tcp.setOption(new char[0]);
			return;
		}
		
		
		char[] opt = new char[(Integer.parseInt(Convert.HextoDec(tcp.getData_Offset()))-5)*8];
		int offset_tcp = this.offset+(Integer.parseInt(Convert.HextoDec(tcp.getData_Offset()))-5)*8;
		
		frame.getChars(this.offset, offset_tcp, opt, 0);
		this.offset = offset_tcp;
		tcp.setOption(opt);
		ArrayList<String> tabRegEx = new ArrayList<String>();
		
		String regex1 = "01"; tabRegEx.add(regex1);
		String regex2 = "0204...."; tabRegEx.add(regex2);
		String regex3 = "0303.."; tabRegEx.add(regex3);
		String regex4 = "0402"; tabRegEx.add(regex4);
		String regex6 = "0606........"; tabRegEx.add(regex6);
		String regex7 = "0706........"; tabRegEx.add(regex7);
		String regex8 = "080a................"; tabRegEx.add(regex8);
		String regex9 = "0902"; tabRegEx.add(regex9);
		String regex10 = "0a03.."; tabRegEx.add(regex10);
		String regex11 = "0b"; tabRegEx.add(regex11);
		String regex12 = "0c"; tabRegEx.add(regex12);
		String regex13 = "0d"; tabRegEx.add(regex13);
		String regex14 = "0e03.."; tabRegEx.add(regex14);
		String regex0 = "00"; tabRegEx.add(regex0);
		
		
		
		String Option = toString(opt);
		
		
		for (String regex : tabRegEx) {
			Pattern pattern = Pattern.compile(regex);
			Matcher matcher = pattern.matcher(Option);
			
			while (matcher.find())
			{
				int i = 0;
				
				if (regex.equals(regex2)) {
					StringBuilder stri = new StringBuilder();
					for (int i1  = 4; i1<8; i1++) {
						stri.append(matcher.group(i).charAt(i1));
					}
					tcp.AddOptions("MSS="+ Convert.HextoDec(stri.toString()));
				}
				
				if (regex.equals(regex3)) {
					StringBuilder stro = new StringBuilder();
					for (int i1  = 4; i1<6; i1++) {
						stro.append(matcher.group(i).charAt(i1));
					}
					tcp.AddOptions("WScale=" + Integer.toString((int)Math.pow(2, Integer.parseInt(Convert.HextoDec(stro.toString()))))); 
				}
				
				if (regex.equals(regex8)) {
					StringBuilder stri = new StringBuilder();
					for (int i1  = 4; i1<12; i1++) {
						stri.append(matcher.group(i).charAt(i1));
					}
					
					StringBuilder stra = new StringBuilder();
					for (int i1  = 12; i1<20; i1++) {
						stra.append(matcher.group(i).charAt(i1));
					}
					
					
					tcp.AddOptions("TSval="+ Convert.HextoDec(stri.toString())+ " TSecr=" + Convert.HextoDec(stra.toString()));
				}
				
				if (regex.equals(regex2)) {
					tcp.AddOptions("SACK_PERM=1");
				}
				i++;
			}
				
				
		  
		}
		
	}
	
	
	public String toString(char[] tab) {
		StringBuilder str = new StringBuilder();
		
		for (int i = 0; i<tab.length; i++) {
			str.append(Character.toString(tab[i]));
		}
		return str.toString();
	}
	
	public String getFrame() {
		// TODO Auto-generated method stub
		return frame;
	}
	
	public String toString() {
		StringBuilder str = new StringBuilder();
		str.append("id: "+ this.getId() +"\n");
		str.append(ethernet.toString());
		str.append(ip.toString());
		str.append(tcp.toString());
		str.append(http.toString());
		
		return str.toString();
	}
	
	public boolean verif() {
		for (int i = 0; i<frame.length(); i++) {
			if(!hexa.contains(Character.toString(frame.charAt(i)))) {
				return false;
			}
		}
		
		return true;
	}

	public Integer getId() {
		return id;
	}


	public static int getCpt() {
		return cpt;
	}


	public int getOffset() {
		return offset;
	}


	public Ethernet getEthernet() {
		return ethernet;
	}


	public IP getIp() {
		return this.ip;
	}


	public TCP getTcp() {
		return tcp;
	}


	public HTTP getHttp() {
		return http;
	}


	public ArrayList<String> getErr() {
		return Err;
	}
	
	

}
