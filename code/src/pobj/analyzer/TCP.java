package pobj.analyzer;

import java.util.*;
import java.math.*;

public class TCP {
	
	private IP ipV4;
	
	private char[] Source_port = new char[4];
	private char[] Destination_port = new char[4];
	private char[] Len = new char[4];
	private char[] Sequence_Number = new char[8];
	private char[] Acknowledgment_Number = new char[8];
	private char[] Data_Offset = new char[1];
	private char[] Flags = new char[3];
	private char[] Reserved = new char[3];
	private char[] URG = new char[1];
	private char[] ACK = new char[1];
	private char[] PSH = new char[1];
	private char[] RST = new char[1];
	private char[] SYN = new char[1];
	private char[] FIN = new char[1];
	private char[] Window = new char[4];
	private char[] Cheksum = new char[4];
	private char[] Urgent_Pointer = new char[4];
	private char[] option;
	private ArrayList<String> Options = new ArrayList<String>();
	private String ChecksumErr = "";
	private int cs = 1;
	
	
	public TCP(IP ipV4) { 
		this.ipV4 = ipV4; 
		this.ChecksumErr = ""; }
	
	public void setSource_port(char[] source_port) {
		Source_port = source_port;
	}

	public void setDestination_port(char[] destination_port) {
		Destination_port = destination_port;
	}

	public void setSequence_Number(char[] sequence_Number) {
		Sequence_Number = sequence_Number;
	}

	public void setAcknowledgment_Number(char[] acknowledgment_Number) {
		Acknowledgment_Number = acknowledgment_Number;
	}
	
	public void setData_Offset(char[] data_Offset) {
		Data_Offset = data_Offset;
	}

	public void setFlags(char[] flags) {
		Flags = flags;
	}

	public void setReserved(char[] reserved) {
		Reserved = reserved;
	}

	public void setWindow(char[] window) {
		Window = window;
	}

	public void setCheksum(char[] cheksum) {
		
		Cheksum = cheksum;
	}

	public void setUrgent_Pointer(char[] urgent_Pointer) {
		Urgent_Pointer = urgent_Pointer;
	}

	public void setOptions(ArrayList<String> options) {
		Options = options;
	}

	public String getSource_port() {
		return Convert.HextoDec(toString(this.Source_port));
	}

	public String getDestination_port() {
		return Convert.HextoDec(toString(this.Destination_port));
	}

	public String getSequence_Number() {
		return Convert.HextoDec(toString(this.Sequence_Number));
	}

	public String getAcknowledgment_Number() {
		return Convert.HextoDec(toString(this.Acknowledgment_Number));
	}

	public String getData_Offset() {
		return toString(Data_Offset);
	} 

	public int getLen() {
		return (Integer.parseInt(Convert.HextoDec(ipV4.getTotal_Length()))
				  - Integer.parseInt(Convert.HextoDec(ipV4.getIHL())) * 4
				  - Integer.parseInt(Convert.HextoDec(this.getData_Offset())) * 4);
	}
	
	public String getTCPLen() {
		return Integer.toHexString((Integer.parseInt(Convert.HextoDec(ipV4.getTotal_Length()))
				  - Integer.parseInt(Convert.HextoDec(ipV4.getIHL())) * 4));
				  
	}

	public String printFlags() {
		
			String flags = "["
					+ ((Integer.parseInt(toString(this.getURG())))>0?" URG ":"")
					+ ((Integer.parseInt(toString(this.getFIN())))>0?" FIN ":"")
					+ ((Integer.parseInt(toString(this.getSYN())))>0?" SYN ":"")
					+ ((Integer.parseInt(toString(this.getRST())))>0?" RST ":"")
					+ ((Integer.parseInt(toString(this.getPSH())))>0?" PSH ":"")
					+ ((Integer.parseInt(toString(this.getACK())))>0?" ACK ":"")
					+ "]";
	
		return flags;
	}
	
	private char[] getFlags() {
		return this.Flags;
	}

	public char[] getReserved() {
		String bin = Convert.HextoBin(toString(this.getFlags()));
		bin.getChars(0, 3, this.Reserved, 0);
		return Reserved;
	}

	public char[] getURG() {
		String bin = Convert.HextoBin(toString(this.getFlags()));
		bin.getChars(6, 7, this.URG, 0);
		return URG;
	}

	public char[] getACK() {
		String bin = Convert.HextoBin(toString(this.getFlags()));
		bin.getChars(7, 8, this.ACK, 0);
		return ACK;
	}

	public char[] getPSH() {
		String bin = Convert.HextoBin(toString(this.getFlags()));
		bin.getChars(8, 9, this.PSH, 0);
		return PSH;
	}

	public char[] getRST() {
		String bin = Convert.HextoBin(toString(this.getFlags()));
		bin.getChars(9, 10, this.RST, 0);
		return RST;
	}

	public char[] getSYN() {
		String bin = Convert.HextoBin(toString(this.getFlags()));
		bin.getChars(10, 11, this.SYN, 0);
		return SYN;
	}

	public char[] getFIN() {
		String bin = Convert.HextoBin(toString(this.getFlags()));
		bin.getChars(11, 12, this.FIN, 0);
		return FIN;
	}

	public String getWindow() {
		return Convert.HextoDec(toString(this.Window));
	}

	public String getCheksum() {
		return toString(Cheksum);
	}

	public String getUrgent_Pointer() {
		return Convert.HextoDec(toString(this.Urgent_Pointer));
	}

	public ArrayList<String> getOptions(){
		return Options;
	}
	
	
	public String printOptions() {
		
		StringBuilder str = new StringBuilder();
		for( String s : Options) {
			str.append(s);
			str.append(" ");
			
		}
		str.append(this.ChecksumErr+" ");
		return str.toString();
	}
	
	public String toString(char[] tab) {
		StringBuilder str = new StringBuilder();
		
		for (int i = 0; i<tab.length; i++) {
			str.append(Character.toString(tab[i]));
		}
		return str.toString();
	}


	public void AddOptions(String group) {
		// TODO Auto-generated method stub
		this.Options.add(group);
		
	}
	
	public String toString() {
		
		StringBuilder str = new StringBuilder();
		
		str.append("Source Port: "+this.getSource_port()+"\n");
		str.append("Destination Port: "+this.getDestination_port()+"\n");
		str.append("TCP Segment Len: "+this.getLen()+ "\n");
		str.append("SN: "+this.getSequence_Number()+ "\n");
		str.append("AN: "+this.getAcknowledgment_Number()+ "\n");
		str.append("Header Length: "+(Integer.parseInt(Convert.HextoDec(this.getData_Offset())) * 4)+ "\n");
		str.append("TCP "+this.printFlags()+ "\n");
		str.append("Window: "+this.getWindow()+ "\n");
		str.append("TCP checksum: "+this.getCheksum()+ "\n");
		str.append("Urgent Pointer: "+this.getUrgent_Pointer()+ "\n");
		str.append("Options TCP: "+this.printOptions()+ "\n");

		return str.toString();
		
	}


	public void setOption(char[] option) {
		this.option = option;
	}

	public String getChecksumErr() {

		return ChecksumErr;
	}
	
	public void verifChecksumTCP() {
		char[] ips = this.ipV4.getSource_Address();
		char[] ipd = this.ipV4.getDestination_Address();
		char[] protocol = {'0','0','0','6'};

		ArrayList<String> CS = new ArrayList<String>();
		CS.add(""+ips[0]+ips[1]+ips[2]+ips[3]);
		CS.add(""+ips[4]+ips[5]+ips[6]+ips[7]);
		CS.add(""+ipd[0]+ipd[1]+ipd[2]+ipd[3]);
		CS.add(""+ipd[4]+ipd[5]+ipd[6]+ipd[7]);
		CS.add(""+toString(protocol));
		
		
		
		CS.add("0000");
		CS.add("00"+getTCPLen());//+this.Data_Offset[0]+this.Data_Offset[0]);
		CS.add(""+toString(this.Source_port));
		CS.add(""+toString(this.Destination_port));
		CS.add(""+Sequence_Number[0]+Sequence_Number[1]+Sequence_Number[2]+Sequence_Number[3]);
		CS.add(""+Sequence_Number[4]+Sequence_Number[5]+Sequence_Number[6]+Sequence_Number[7]);
		CS.add(""+Acknowledgment_Number[0]+Acknowledgment_Number[1]+Acknowledgment_Number[2]+Acknowledgment_Number[3]);
		CS.add(""+Acknowledgment_Number[4]+Acknowledgment_Number[5]+Acknowledgment_Number[6]+Acknowledgment_Number[7]);
		CS.add(""+this.Data_Offset[0]+this.Flags[0]+this.Flags[1]+this.Flags[2]);
		CS.add(""+Window[0]+Window[1]+Window[2]+Window[3]);
		CS.add("0000");
		CS.add(""+this.Urgent_Pointer[0]+Urgent_Pointer[1]+Urgent_Pointer[2]+Urgent_Pointer[3]);
		for (int i = 0; i<option.length; i+=4){
			CS.add(""+option[i]+option[i+1]+option[i+2]+option[i+3]);
		}
		
		if (!Convert.HexListtoCS(CS).equals(toString(this.Cheksum))) {
			this.ChecksumErr = "[TCP CHECKSUM INCORRECT]";
			this.cs = 0;
		}
	}

	public int getCs() {
		return cs;
	}
	
	
	
	
	
}
