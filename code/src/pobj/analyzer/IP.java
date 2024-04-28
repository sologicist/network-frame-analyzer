package pobj.analyzer;

import java.util.ArrayList;

public class IP {
	
	private char[] Version = new char[1];
	private char[] IHL = new char[1];
	private char[] TOS = new char[2];
	private char[] Total_Length = new char[4];
	private char[] Identification = new char[4];
	private char[] Flags = new char[1]; //a verifier
	private char[] Fragment_offset = new char[3];
	private char[] TTL = new char[2];
	private char[] Protocol = new char[2];
	private char[] Header_Checksum = new char[4];
	private char[] Source_Address = new char[8];
	private char[] Destination_Address = new char[8];
	private char[] OptionsandPadding = new char[0];
	private String ChecksumErr = "";
	 
	public IP() {
		
	}
	
	public void IP_option() {
		int THL = Integer.parseInt(Convert.HextoDec(toString(IHL)));
		this.OptionsandPadding = new char[(THL-5)*8]; //1 octet = 2 char
		this.ChecksumErr = "";
	}

	public void setVersion(char[] version) throws AnalyzerException {
		if (Integer.parseInt(Convert.HextoDec(toString(version))) != 4) throw new AnalyzerException("Ce n'est pas une trame IPV4");
		Version = version;
	}

	public void setIHL(char[] iHL) {
		IHL = iHL;
	}

	public void setTOS(char[] tOS) {
		TOS = tOS;
	}

	public void setTotal_Length(char[] total_Length) {
		Total_Length = total_Length;
	}

	public void setIdentification(char[] identification) {
		Identification = identification;
	}

	public void setFlags(char[] flags) {
		Flags = flags;
	}

	public void setFragment_offset(char[] fragment_offset) {
		Fragment_offset = fragment_offset;
	}

	public void setTTL(char[] tTL) {
		TTL = tTL;
	}

	public void setProtocol(char[] protocol) throws AnalyzerException {
		if (Integer.parseInt(Convert.HextoDec(toString(protocol))) != 6) throw new AnalyzerException("Cette trame n'encapsule pas de paquet TCP");
		Protocol = protocol;
	}

	public void setHeader_Checksum(char[] header_Checksum) {
		Header_Checksum = header_Checksum;
	}

	public void setSource_Address(char[] source_Address) {
		Source_Address = source_Address;
	}

	public void setDestination_Address(char[] destination_Address) {
		Destination_Address = destination_Address;
	}

	public void setOptionsandPadding(char[] optionsandPadding) {
		OptionsandPadding = optionsandPadding;
	}

	public String getVersion() {
		return toString(Version);
	}

	public String getIHL() {
		return toString(IHL);
	}

	public String getTOS() {
		return toString(TOS);
	}

	public String getTotal_Length() {
		return toString(Total_Length);
	}

	public String getIdentification() {
		return toString(Identification);
	}

	public String getFlags() {
		return toString(Flags);
	}

	public String getFragment_offset() {
		return toString(Fragment_offset);
	}

	public String getTTL() {
		return toString(TTL);
	}

	public String getProtocol() {
		return toString(Protocol);
	}

	public String getHeader_Checksum() {
		return toString(Header_Checksum);
	}
	
	

	public char[] getSource_Address() {
		return Source_Address;
	}

	public char[] getDestination_Address() {
		return Destination_Address;
	}

	public String getIP_Destination() {
		String ip_destination = "";
		
		for(int i = 0; i<this.Destination_Address.length; i+=2) {
			ip_destination += Convert.HextoDec(Character.toString(this.Destination_Address[i])
					+ Character.toString(this.Destination_Address[i+1]));
			if (i+2 < this.Destination_Address.length) {
				ip_destination += "."; 
			}
		}
		
		return ip_destination;
	}

	public String getIP_Source() {
		String ip_source = "";
		
		for(int i = 0; i<this.Source_Address.length; i+=2) {
			ip_source += Convert.HextoDec(Character.toString(this.Source_Address[i])
										+ Character.toString(this.Source_Address[i+1]));
			if (i+2 < this.Source_Address.length) {
				ip_source += "."; 
			}
			
		}
		
		return ip_source;
	}
	
	
	public char[] getOptionsandPadding() {
		return OptionsandPadding;
	}
	
	public String getChecksumErr() {
		return ChecksumErr;
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
		
		str.append("Version: "+this.getVersion()+"\n");
		str.append("Header Length: "+Integer.parseInt(this.getIHL())*4+" bytes "+"("+this.getIHL()+")"+"\n");
		str.append("DSF: "+"0x"+this.getTOS()+"\n");
		str.append("Total Length: "+Convert.HextoDec(this.getTotal_Length())+"\n");
		str.append("Identification: "+"0x"+this.getIdentification()+" ("+Convert.HextoDec(this.getIdentification())+")"+"\n");
		str.append("Total Length: "+Convert.HextoDec(this.getTotal_Length())+"\n");
		str.append("Flags: "+"0x"+this.getFlags()+"\n");
		str.append("Fragment Offset: "+Convert.HextoDec(this.getFragment_offset())+"\n");
		str.append("Time To Live: "+Convert.HextoDec(this.getTTL())+"\n");
		str.append("Protocol: TCP"+" ("+Convert.HextoDec(this.getProtocol())+")"+"\n");
		str.append("Source Address: "+this.getIP_Source()+"\n");
		str.append("Destination Adress: "+this.getIP_Destination()+"\n");
		str.append("Option "+"("+this.OptionsandPadding.length/2+" bytes): "+(this.OptionsandPadding.length > 0?(this.getOptionsandPadding()):"No data")+"\n");
		
		
		return str.toString();
	}

	
}