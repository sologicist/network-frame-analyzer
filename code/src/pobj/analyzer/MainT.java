package pobj.analyzer;

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Scanner;

public class MainT {
	
	private static String path = "";
	private static String pathexport = "";
	private static ArrayList<ArrayList<String>> res = new ArrayList<ArrayList<String>>();
	private static ArrayList<ArrayList<String>> tmp = new ArrayList<ArrayList<String>>();
	private static ArrayList<ArrayList<String>> coupleIP = new ArrayList<ArrayList<String>>();
	private static int cpt = 0;
	private static String print = "";
	
	public static void main(String[] args) throws AnalyzerException, FileNotFoundException {
		
		while(true){
			
			System.out.println("Veuillez fournir le chemin du fichier comprenant les trames au format : /home/.../ [! Ne pas oublier les slashs en debut et fin !] \nou indiquer le terme exit pour quitter le programme.");
			Scanner scanner = new Scanner(System.in);
			path = scanner.nextLine();
			System.out.println("Path is " + path);
			if (path.toLowerCase().equals("exit")) {System.out.println("Vous quittez le programme."); return ;}
			if (path.toLowerCase().equals("")) {continue;}
			String file = path;
	    	
	    	System.out.println("Veuillez indiquer le chemin du dossier afin d'y enregistrer le résultats du visualisateur. Format : /home/.../ [! Ne pas oublier les slashs en debut et fin !] \nou indiquer le terme back pour revenir à la selection.\"");
			Scanner scannerex = new Scanner(System.in);
			pathexport = scannerex.nextLine();
			if (pathexport.toLowerCase().equals("exit")) {System.out.println("Vous quittez le programme."); return ;}
			if (pathexport.toLowerCase().equals("back")) { continue ;}
			
			System.out.println("\n");
	    	BulkAnalyzer b = new BulkAnalyzer();
			try{b.analyzer(path);} catch(Exception e) { System.out.println("Fichier introuvable"); return; }
			try {
				b.sequencer();
			} catch (AnalyzerException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			b.row();
			res = b.getFinalres();
			
			initialize(file);
	    	coupleIP = couple(res);
	    	if (coupleIP.size() == 0) {System.out.println("No data found."); continue;}
	    	//
	    	for (ArrayList<String> s : coupleIP) {
	    		print+=initializePack(file, s.get(0), s.get(1));
	    		print+="\n"+"\n";
	    	}
	    	StringBuilder log = new StringBuilder();
	    	log.append("");
	    	for (int i = 0; i < b.getFrames().size(); i++) {
	    		for (int it =0; it < b.getFrames().get(i).getErr().size(); it++) {
	    			log.append("Trame "+(i+1)+" : "+b.getFrames().get(i).getErr().get(it)+"\n");
	    		}
	    		
	    	}
	    	
	    	PrintWriter writerlog = new PrintWriter(pathexport+"Log"+cpt);
			writerlog.println(log.toString());
			writerlog.close();
			
	    	
	    	System.out.println(print);
			PrintWriter writer = new PrintWriter(pathexport+"Analyse"+cpt);
			writer.println(print);
			writer.close();
			
			System.out.println("Le fichier d'erreur est enregistré dans :"+pathexport+" et a pour nom : Log"+cpt);
			System.out.println("Le fichier d'analyse est enregistré dans :"+pathexport+" et a pour nom : Analyse"+cpt);
			System.out.println("\n"+"\n");
			cpt++;
			while(true) {
				print = "";
				System.out.println("Voulez vous filtrer votre recherche ? Format du filtre : Protocol IP_source IP_destination [! vide dans les champs non voulus !] (e.g. TCP 65.208.228.223 145.254.160.237) \nou revenir à la selection des trames en indiquant le terme back.");
				Scanner scannerfiltre = new Scanner(System.in);
				String filtre = scannerfiltre.nextLine();
				String[] splitter = filtre.split(" "); 
				if (splitter.length == 3 && (splitter[0].toLowerCase().equals("ip") || splitter[0].toLowerCase().equals("tcp") || splitter[0].toLowerCase().equals("http") || splitter[0].toLowerCase().equals("vide"))) {
					b.filtreALL(splitter[0].toUpperCase(), splitter[1].toUpperCase(), splitter[2].toUpperCase());
				
					res = b.getFinalres();
					if (res.size() == 0 || res == null) {System.out.println("No data found."); continue;}
					coupleIP = couple(res);
					
					tmp = b.getFinalres();
			    	for (ArrayList<String> s : coupleIP) {
			    		print+=initializePack(file, s.get(0), s.get(1));
			    		print+="\n"+"\n";
			    	}
			    	tmp = new ArrayList<ArrayList<String>>();
					
			    	System.out.println(print);
					PrintWriter writerfiltre = new PrintWriter(pathexport+"Analyse"+cpt++);
					writerfiltre.println(print);
					writerfiltre.close();
					
					System.out.println("Le fichier est enregistré dans :"+pathexport);
					System.out.println("\n");
				}
				if (splitter.length == 1 && splitter[0].toLowerCase().equals("back")) {
					break;
				}
				
				b = new BulkAnalyzer();
				try{b.analyzer(path);} catch(Exception e) { System.out.println("Fichier introuvable"); return; }
				try {
					b.sequencer();
				} catch (AnalyzerException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				b.row();
				initialize(path);

			}
			
			print="";
		}
	}
	public static void initialize(String path) throws AnalyzerException {
		BulkAnalyzer b = new BulkAnalyzer();
		try{b.analyzer(path);} catch(Exception e) { System.out.println("Fichier introuvable"); return; }
		try {
			b.sequencer();
		} catch (AnalyzerException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		b.row();
		res = b.getFinalres();
	}
		
	
	public static String initializePack(String path, String Is, String Id) throws AnalyzerException, FileNotFoundException {
		BulkAnalyzer b = new BulkAnalyzer();
		try{b.analyzer(path);} catch(Exception e) { System.out.println("Fichier introuvable."); return null; }
		try {
			b.sequencer();
		} catch (AnalyzerException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		b.row();
		
		if(tmp.size() > 0) {b.setFinalres(tmp);}
		String IPS = Is;
		String IPD = Id;
		
		String res ="";
		for (int it = 0; it<15-b.getFinalres().get(0).get(1).length(); it++) {
			IPS = " "+IPS;
		}
		for (int it = 0; it<15-b.getFinalres().get(0).get(2).length(); it++) {
			IPD = " "+IPD;
		}
		res+="         "+IPS; res+="                    "+IPD; res+="       "+"Comment :"; res+="\n";
		
		for (int i = 0; i < b.getFinalres().size(); i++) {
			
			if (b.getFinalres().get(i).get(1).equals(Is.trim()) && b.getFinalres().get(i).get(2).equals(Id.trim())) {
				String num =" "+Integer.toString(Integer.parseInt(b.getFinalres().get(i).get(0).trim())+1);
				for (int it = 0; it<4-b.getFinalres().get(i).get(0).length(); it++) {
					num = " "+num;
				}
				String ports = "       "+b.getFinalres().get(i).get(3);
				for (int it = 0; it<5-b.getFinalres().get(i).get(3).length(); it++) {
					ports = " "+ports;
				}
				String flux = " | ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~> | ";
				String portd = ""+b.getFinalres().get(i).get(4);
				for (int it = 0; it<5-b.getFinalres().get(i).get(4).length(); it++) {
					portd = " "+portd;
				}
				String comment = "        "+b.getFinalres().get(i).get(6);
				res+=num+ports+flux+portd+comment;
				res+="\n";
			}
		
			if (b.getFinalres().get(i).get(1).equals(Id.trim()) && b.getFinalres().get(i).get(2).equals(Is.trim())) {
				String num =" "+Integer.toString(Integer.parseInt(b.getFinalres().get(i).get(0).trim())+1);
				for (int it = 0; it<4-b.getFinalres().get(i).get(0).length(); it++) {
					num = " "+num;
				}
				String ports = "       "+b.getFinalres().get(i).get(4);
				for (int it = 0; it<5-b.getFinalres().get(i).get(4).length(); it++) {
					ports = " "+ports;
				}
				String flux = " | <~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ | ";
				String portd = ""+b.getFinalres().get(i).get(3);
				for (int it = 0; it<5-b.getFinalres().get(i).get(3).length(); it++) {
					portd = " "+portd;
				}
				String comment = "        "+b.getFinalres().get(i).get(6);
				
				res+=num+ports+flux+portd+comment;
				res+="\n";

			}	
		}
			
		return res;
	}
	
	public static ArrayList<ArrayList<String>> couple(ArrayList<ArrayList<String>> l){
		if (l.size()==0) {return new ArrayList<ArrayList<String>>(); }
		ArrayList<ArrayList<String>> total = new ArrayList<ArrayList<String>>();
		int pres = 0;
		for (int i = 0; i<l.size(); i++) {
			ArrayList<String> c = new ArrayList<String>();
			c.add(l.get(i).get(1));
			c.add(l.get(i).get(2));
			for (int it = 0; it<total.size(); it++){
				if (total.get(it).contains(c.get(0)) && total.get(it).contains(c.get(1))) {
					pres=1;
				}			
			}
			if(pres == 0) {total.add(c);}
			pres=0;
			
		}
		for (int i=0; i<total.size(); i++) {
			total.get(i).get(0);
		}

		return total;
		
	}
	
}
