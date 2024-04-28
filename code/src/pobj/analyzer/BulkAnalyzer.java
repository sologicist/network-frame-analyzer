package pobj.analyzer;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;

public class BulkAnalyzer {

	private ArrayList<Frame> frames;
	private Map<Integer, ArrayList<ArrayList<String>>> res = new HashMap<>(); 
	private ArrayList<ArrayList<String>> finalres = new ArrayList<ArrayList<String>>();
	
	
	public BulkAnalyzer() {}

		
	public ArrayList<Frame> analyzer(String path) {
		frames = new ArrayList<Frame>();
		String tmp = "";
		try (BufferedReader br = new BufferedReader(new FileReader(path))) {
			 for (String line = br.readLine() ; line != null ; line = br.readLine() ) {
				
				line = line.replaceAll("   \\s+", "   ");
				
				String[] pline = line.split("   ");
				 
				if (pline.length < 2) continue;
				
				if (pline[0].equals("0000")){
					
					if(!tmp.equals("")) frames.add(new Frame(tmp));
					tmp = "";
					tmp+=pline[1].toLowerCase().replaceAll(" ", "");	
				}
				
				else {
					
					tmp+=pline[1].toLowerCase().replaceAll(" ", "");;
				}
				
			 }
			 
			 frames.add(new Frame(tmp));
			  
		 } catch (IOException e) {
			 e.printStackTrace();
		 }
		
		
		/*for(Frame f : frames) {
			System.out.println(f.getFrame());		
		}*/
		return frames;	
	}
	
	public void sequencer() throws AnalyzerException {

		ArrayList<Frame> frames = this.getFrames();
		int i = 0;
		for(Frame f : frames) {
			f.analyzer();
			//System.out.println(f.toString());

			ArrayList<String> data = new ArrayList<String>();
			ArrayList<String> Infos = new ArrayList<String>();
			if(f.getErr().size() == 0) {
				data.add(f.getIp().getIP_Source()); data.add(f.getIp().getIP_Destination()); data.add(!f.getEthernet().getType().equals("0800")? "Type non pris en charge" :
																									  !(Convert.HextoDec(f.getIp().getProtocol()).equals("6"))? "Protocol non pris en charge" :
																									  f.getHttp().getRequest().isEmpty()? "TCP" : "HTTP");
			
				data.add(Integer.toString(f.getFrame().length()/2));
				
				if((Convert.HextoDec(f.getIp().getProtocol()).equals("6")) && f.getHttp().getRequest().isEmpty()) {
					Infos.add(f.getTcp().getSource_port()); Infos.add(f.getTcp().getDestination_port()); 
					Infos.add(f.getTcp().printFlags());
					Infos.add("Seq: "+f.getTcp().getSequence_Number());
					Infos.add("Ack: "+f.getTcp().getAcknowledgment_Number());
					Infos.add("Win: "+f.getTcp().getWindow());
					if(f.getIp().getChecksumErr().length()>0) {
						Infos.add(f.getIp().getChecksumErr());
					}
					if(f.getTcp().getChecksumErr().length()>0) {
						Infos.add(f.getTcp().getChecksumErr()+" Len="+f.getTcp().getLen());
					}
					else{Infos.add("Len="+f.getTcp().getLen());}
					Infos.add(f.getTcp().printOptions());
					
				}
				else {
					if ((Convert.HextoDec(f.getIp().getProtocol()).equals("6")) && f.getHttp().getRequest().size()>0) {
						Infos.add(f.getTcp().getSource_port()); Infos.add(f.getTcp().getDestination_port()); 
						Infos.add(Convert.HextoText(f.getHttp().getHead_req()));
					}
				}

			}
			
			else{
				
				data.add("No Data");data.add("No Data");data.add(f.getErr().get(0));data.add("No Data");
			
				Infos.add("No Data");Infos.add("No Data");Infos.add("No Data");Infos.add("No Data");
				Infos.add("No Data");Infos.add("No Data");Infos.add("No Data");Infos.add("No Data");
			}
				
			ArrayList<ArrayList<String>> fin = new ArrayList<ArrayList<String>>();
			fin.add(data); fin.add(Infos);
			
			res.put(i, fin);
			
			i++;

		}
		
	}
	
	public void printFG() {

		ArrayList<ArrayList<String>> row = row();
		
		for (int it = 0; it < this.getFrames().size(); it++) {
			StringBuilder str = new StringBuilder();
			str.append(row.get(it).get(0)); str.append(" ");
			str.append(row.get(it).get(1)); str.append(" ");
			str.append(row.get(it).get(2)); str.append(" ");
			str.append(row.get(it).get(3)); str.append(" ");
			str.append(row.get(it).get(5)); str.append(" ");
			str.append(row.get(it).get(4)); str.append(" ");
			str.append(row.get(it).get(6)); str.append(" ");
			
			System.out.println(str.toString());
		}
		
		
	}
	
	public ArrayList<ArrayList<String>> row(){
		ArrayList<ArrayList<String>> row = new ArrayList<ArrayList<String>>();
		//System.out.println(res.size());
		//System.out.println(getFrames().size());
		
		for (int it = 0; it < getFrames().size(); it++) {
			//System.out.println(res.get(it).get(0).get(0).equals("No Data"));
			if(!res.get(it).get(0).get(0).equals("No Data")) {
				
				ArrayList<String> rowi = new ArrayList<String>();
				rowi.add("  "+Integer.toString(it));     //id trame
				rowi.add(res.get(it).get(0).get(0)); // ip source
				rowi.add(res.get(it).get(0).get(1));	//ip destination
				
				rowi.add(res.get(it).get(1).get(0)); //port source
				rowi.add(res.get(it).get(1).get(1)); //port destination
				StringBuilder arrow = new StringBuilder();
				//System.out.println(getFrames().get(it).getHttp().getRequest());
				if((Convert.HextoDec(getFrames().get(it).getIp().getProtocol()).equals("6")) && getFrames().get(it).getHttp().getRequest().isEmpty()) {
					arrow.append(res.get(it).get(1).get(0)+" ➔ "+res.get(it).get(1).get(1));arrow.append(" ");
					arrow.append(res.get(it).get(1).get(2)); arrow.append(" "); //flags
					arrow.append(res.get(it).get(1).get(3)); arrow.append(" "); //seq
					arrow.append(res.get(it).get(1).get(4)); arrow.append(" "); //ack
					arrow.append(res.get(it).get(1).get(5)); arrow.append(" "); //window
					arrow.append(res.get(it).get(1).get(6)); arrow.append(" "); //len
					arrow.append(res.get(it).get(1).get(7)); arrow.append(" "); //option
					
				}
				else {
					if ((Convert.HextoDec(getFrames().get(it).getIp().getProtocol()).equals("6")) && getFrames().get(it).getHttp().getRequest().size()>0) {
						arrow.append(res.get(it).get(1).get(2)); //res HTTP
					}
				}
				rowi.add(arrow.toString());
				
				
				
				
				StringBuilder comment = new StringBuilder();
				comment.append(res.get(it).get(0).get(2)+": "); //protocol
				comment.append(arrow.toString());  //arrow
				
				
				
				rowi.add(comment.toString());	
				rowi.add(res.get(it).get(0).get(2)); //protocol
				rowi.add(Integer.toString(getFrames().get(it).getTcp().getCs()));
				row.add(rowi);

			}else {
				ArrayList<String> rowi = new ArrayList<String>();
				rowi.add("  "+Integer.toString(it));     //id trame
				rowi.add(res.get(it).get(0).get(0)); // ip source
				rowi.add(res.get(it).get(0).get(1));	//ip destination
				
				rowi.add(res.get(it).get(1).get(0)); //port source
				rowi.add(res.get(it).get(1).get(1)); //port destination
				rowi.add(getFrames().get(it).getErr().get(0));
				rowi.add(getFrames().get(it).getErr().get(0));
				rowi.add("No Data");
			}
			
			
		}
		
		finalres = row;
		return row;
		
	}
	
	public ArrayList<ArrayList<String>> filtreALL(String flow, String IPS, String IPD) {
		ArrayList<ArrayList<String>> filtre = new ArrayList<ArrayList<String>>();
		ArrayList<ArrayList<String>> CBF = new ArrayList<ArrayList<String>>();
		ArrayList<String> ipxs = new ArrayList<String>();
		ArrayList<String> ipxd = new ArrayList<String>();
		
		if(!flow.trim().equals("") && !flow.trim().toUpperCase().equals("IPV4") && !flow.trim().toUpperCase().equals("IP") && !flow.trim().toLowerCase().equals("vide")) {
			for (int i = 0; i<this.finalres.size(); i++) {
				if(this.finalres.get(i).get(7).equals(flow)) {
					filtre.add(this.finalres.get(i));
					if(!ipxs.contains(finalres.get(i).get(1))) {ipxs.add(finalres.get(i).get(1));}
					if(!ipxd.contains(finalres.get(i).get(2))) {ipxd.add(finalres.get(i).get(2));}
				}
			}
			
		}else {
			for (int i = 0; i<this.finalres.size(); i++) {
				filtre.add(this.finalres.get(i));
				if(!ipxs.contains(finalres.get(i).get(1))) {ipxs.add(finalres.get(i).get(1));}
				if(!ipxd.contains(finalres.get(i).get(2))) {ipxd.add(finalres.get(i).get(2));}
			}
		}
		
		ArrayList<ArrayList<String>> filtre2 = new ArrayList<ArrayList<String>>();
		if(!IPS.trim().equals("") && !IPS.trim().toLowerCase().equals("vide")) {
			for (int i = 0; i<filtre.size(); i++) {
				if(filtre.get(i).get(1).equals(IPS)) {
					filtre2.add(filtre.get(i));
					if(!ipxs.contains(IPS)) {ipxs.add(IPS);}
					if(!ipxd.contains(filtre.get(i).get(2))) {ipxd.add(filtre.get(i).get(2));}		
				}
			}
		}else {
			for (int i = 0; i<filtre.size(); i++) {
				filtre2.add(filtre.get(i));
				if(!ipxs.contains(filtre.get(i).get(1))) {ipxs.add(filtre.get(i).get(1));}
				if(!ipxd.contains(filtre.get(i).get(2))) {ipxd.add(filtre.get(i).get(2));}	
			}
		}
		
		ArrayList<ArrayList<String>> filtre3 = new ArrayList<ArrayList<String>>();
		if(!IPD.trim().equals("") && !IPD.trim().toLowerCase().equals("vide")) {
			for (int i = 0; i<filtre2.size(); i++) {
				if(filtre2.get(i).get(2).equals(IPD)) {
					filtre3.add(filtre2.get(i));
					if(!ipxs.contains(filtre2.get(i).get(1))) {ipxs.add(filtre2.get(i).get(1));}
					if(!ipxd.contains(IPD)) {ipxd.add(IPD);}		
				}
			}
		}else {
			for (int i = 0; i<filtre2.size(); i++) {
				filtre3.add(filtre2.get(i));
				if(!ipxs.contains(filtre2.get(i).get(1))) {ipxs.add(filtre2.get(i).get(1));}
				if(!ipxd.contains(filtre2.get(i).get(2))) {ipxd.add(filtre2.get(i).get(2));}	
			
			}
		}
			CBF.add(ipxs); CBF.add(ipxd);
			
			this.finalres = filtre3;
			return CBF;
		
	}

	public ArrayList<Frame> getFrames() {
		return frames;
	}

	public ArrayList<ArrayList<String>> getFinalres() {
		return finalres;
	}


	public void setFinalres(ArrayList<ArrayList<String>> finalres) {
		this.finalres = finalres;
	}
	
	
	
	
}
