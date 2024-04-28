package pobj.analyzer;

import java.io.IOException;
import java.math.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Convert {

	private Convert(){}
	
	
	public static String HextoDec(String str) {
		BigInteger res = new BigInteger(str, 16);
		return res.toString();
	}
	
	public static String HextoBin(String hex) {
		hex = hex.replaceAll("0", "0000");
        hex = hex.replaceAll("1", "0001");
        hex = hex.replaceAll("2", "0010");
        hex = hex.replaceAll("3", "0011");
        hex = hex.replaceAll("4", "0100");
        hex = hex.replaceAll("5", "0101");
        hex = hex.replaceAll("6", "0110");
        hex = hex.replaceAll("7", "0111");
        hex = hex.replaceAll("8", "1000");
        hex = hex.replaceAll("9", "1001");
        hex = hex.replaceAll("a", "1010");
        hex = hex.replaceAll("b", "1011");
        hex = hex.replaceAll("c", "1100");
        hex = hex.replaceAll("d", "1101");
        hex = hex.replaceAll("e", "1110");
        hex = hex.replaceAll("f", "1111");
        
        return hex;
	}
	
	public static String BintoHex(String binary) {
		String res = "";
		for (int i = 0; i<binary.length(); i+=4){
			String bin = ""+binary.charAt(i)+binary.charAt(i+1)+binary.charAt(i+2)+binary.charAt(i+3);
			
			bin = bin.replaceAll("0000", "0");
			bin = bin.replaceAll("0001", "1");
			bin = bin.replaceAll("0010", "2");
			bin = bin.replaceAll("0011", "3");
			bin = bin.replaceAll("0100", "4");
			bin = bin.replaceAll("0101", "5");
			bin = bin.replaceAll("0110", "6");
			bin = bin.replaceAll("0111", "7");
			bin = bin.replaceAll("1000", "8");
			bin = bin.replaceAll("1001", "9");
			bin = bin.replaceAll("1010", "a");
			bin = bin.replaceAll("1011", "b");
			bin = bin.replaceAll("1100", "c");
			bin = bin.replaceAll("1101", "d");
			bin = bin.replaceAll("1110", "e");
			bin = bin.replaceAll("1111", "f");
			
			res+=bin;
		}
		
        
        return res;
	}
	
	public static String comp(String hex) {
		hex = hex.replaceAll("0", "x");
        hex = hex.replaceAll("1", "0");
        hex = hex.replaceAll("x", "1");
       
        return hex;
	}
	
	
	public static String HextoText(String str) {
		int l = str.length();
	    byte[] data = new byte[l / 2];
	    for (int i = 0; i < l; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(str.charAt(i), 16) << 4)
	                + Character.digit(str.charAt(i + 1), 16));
	    }
		return new String(data, StandardCharsets.UTF_8);
	}
	
	
	
	public static String HexListtoCS(ArrayList<String> cs) {
		int sum = 0;
		for(String s : cs) {
			sum+=Integer.parseInt(HextoDec(s));
		}
		String t = Integer.toHexString(sum);
		if (t.length()>4) {
			String t1 = ""+t.charAt(t.length()-4)+t.charAt(t.length()-3)+t.charAt(t.length()-2)+t.charAt(t.length()-1);
			String t2 = "";
			for(int i = 0; i < t.length()-4; i++) {
				t2 = ""+t.charAt(i);
			}
		
			sum=Integer.parseInt(HextoDec(t1))+Integer.parseInt(HextoDec(t2));
		}
		else {
			return Integer.toHexString(sum);
		}
		
		String res = Integer.toHexString(sum); res = HextoBin(res);
		
		return BintoHex(comp(res));
	}
	
	public static void main(String[]args) throws IOException {
	}
	
}