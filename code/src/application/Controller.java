package application;
import pobj.analyzer.*;

import java.awt.Desktop;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;

import javax.print.DocFlavor.URL;

import javafx.collections.FXCollections;
import javafx.collections.ObservableList;
import javafx.event.ActionEvent;

import javafx.fxml.FXML;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ChoiceBox;
import javafx.scene.control.Label;
import javafx.scene.control.Menu;
import javafx.scene.control.MenuItem;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.cell.PropertyValueFactory;
import javafx.scene.layout.AnchorPane;
import javafx.scene.layout.Region;
import javafx.stage.FileChooser;
import javafx.stage.FileChooser.ExtensionFilter;
import javafx.stage.Stage;
import pobj.analyzer.AnalyzerException;
import pobj.analyzer.BulkAnalyzer;

public class Controller {
	
	@FXML
    private Stage stage;
	
	@FXML
    private AnchorPane anchor;

    @FXML
    private TableColumn<Flow, String> arrow;

    @FXML
    private TableColumn<Flow, String> comment;

    @FXML
    private ChoiceBox<String> dest;

    @FXML
    private Label flow;

    @FXML
    private TableView<Flow> flowgraph;

    @FXML
    private TableColumn<Flow, String> frame;

    @FXML
    private Label ipdest;

    @FXML
    private Label ipdestfinale;

    @FXML
    private Label ipsource;

    @FXML
    private Label ipsrc;

    @FXML
    private TableColumn<Flow, String> portdest;

    @FXML
    private TableColumn<Flow, String> portsrc;

    @FXML
    private ChoiceBox<String> src;

    @FXML
    private Button visu;
    
    @FXML
    private MenuItem importfile;
    
    private String res;
    
    
    @FXML
    private ChoiceBox<String> protocol;
    
    private String path;
    
    
    
    @FXML
    private void importpath(ActionEvent event) throws AnalyzerException {
    	event.consume();
    	FileChooser chooser = new FileChooser();
        File file = chooser.showOpenDialog(new Stage());
        if (file != null) {
            path = file.toString();
        }	
    }
    
    
    @FXML
    private void printtab(ActionEvent event) throws AnalyzerException, FileNotFoundException {
        event.consume();
        
        BulkAnalyzer b = new BulkAnalyzer();
    	String file = path;
    	
		b.analyzer(file);
		b.sequencer();
		b.row();
		
		String flowt = "";
		String sooooooorc = "";
		String deeeeeest = "";
		
    	if (protocol.getValue() != null) {
			flowt = (String) this.protocol.getValue();
			
		}
		
		if (this.src.getValue() != null) {
			sooooooorc = (String) this.src.getValue();
			
		}
		if (this.dest.getValue() != null) {
			deeeeeest = (String) this.dest.getValue();
		}
		
    	ArrayList<ArrayList<String>> filtre = b.filtreALL(flowt, sooooooorc, deeeeeest);
		ObservableList<String> proto = FXCollections.observableArrayList("", "IP", "TCP", "HTTP");
    	
	    this.protocol.setItems(proto);
    	
    	ObservableList<String> sourceips = FXCollections.observableArrayList(); sourceips.add("");
    	for(String s : filtre.get(0)) {
    		sourceips.add(s);
    	}
    	this.src.setItems(sourceips);
    	
    	ObservableList<String> sourceipd = FXCollections.observableArrayList(); sourceipd.add("");
    	for(String s : filtre.get(1)) {
    		sourceipd.add(s);
    	}
    	this.dest.setItems(sourceipd);

		
		if (b.getFinalres().size()>0) {
		String IPS =  b.getFinalres().get(0).get(1);
		String IPD =  b.getFinalres().get(0).get(2);
		
		ObservableList<Flow> flowx = FXCollections.observableArrayList();
		this.res="";
		for (int it = 0; it<15-b.getFinalres().get(0).get(1).length(); it++) {
			IPS = " "+IPS;
		}
		for (int it = 0; it<15-b.getFinalres().get(0).get(2).length(); it++) {
			IPD = " "+IPD;
		}
		res+="         "+IPS; res+="                    "+IPD; res+="       "+"Comment :"; res+="\n";
		for (int i = 0; i < b.getFinalres().size(); i++) {
			if (b.getFinalres().get(i).get(1).equals(IPS.trim()) && b.getFinalres().get(i).get(2).equals(IPD.trim())) {
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
				flowx.add(new Flow(Integer.toString(Integer.parseInt(b.getFinalres().get(i).get(0).trim())+1), b.getFinalres().get(i).get(3), b.getFinalres().get(i).get(5)+"\n"+"------------------------------------------------------------------------------------------------------------------------------------------------------------------->", b.getFinalres().get(i).get(4), b.getFinalres().get(i).get(6)));
			}
			if (b.getFinalres().get(i).get(1).equals(IPD.trim()) && b.getFinalres().get(i).get(2).equals(IPS.trim())) {
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
				flowx.add(new Flow(Integer.toString(Integer.parseInt(b.getFinalres().get(i).get(0).trim())+1), b.getFinalres().get(i).get(4), b.getFinalres().get(i).get(5)+"\n"+"<-------------------------------------------------------------------------------------------------------------------------------------------------------------------", b.getFinalres().get(i).get(3), b.getFinalres().get(i).get(6)));
			}	
		}
		
		
		
		ipsource.setText(IPS);
		ipdestfinale.setText(IPD);
    	
    	frame.setCellValueFactory(new PropertyValueFactory<Flow, String>("frame"));
    	portsrc.setCellValueFactory(new PropertyValueFactory<Flow, String>("portsrc"));
    	arrow.setCellValueFactory(new PropertyValueFactory<Flow, String>("arrow"));
    	portdest.setCellValueFactory(new PropertyValueFactory<Flow, String>("portdest"));
    	comment.setCellValueFactory(new PropertyValueFactory<Flow, String>("comment"));
    	
    	flowgraph.setItems(flowx);
		}
		else {
			frame.setCellValueFactory(new PropertyValueFactory<Flow, String>("frame"));
	    	portsrc.setCellValueFactory(new PropertyValueFactory<Flow, String>("portsrc"));
	    	arrow.setCellValueFactory(new PropertyValueFactory<Flow, String>("arrow"));
	    	portdest.setCellValueFactory(new PropertyValueFactory<Flow, String>("portdest"));
	    	comment.setCellValueFactory(new PropertyValueFactory<Flow, String>("comment"));
	    	ObservableList<Flow> flowz = FXCollections.observableArrayList(
	    			new Flow(" No data", " No data", " No data", " No data", " No data"));
	    	flowgraph.setItems(flowz);
			
		}
		
        StringBuilder log = new StringBuilder();
	    	log.append("");
	    	for (int i = 0; i < b.getFrames().size(); i++) {
	    		for (int it =0; it < b.getFrames().get(i).getErr().size(); it++) {
	    			log.append("Trame "+(i+1)+" : "+b.getFrames().get(i).getErr().get(it)+"\n");
	    		}
	    		
	    	}
	    	
	    	System.out.println("Error : \n"+log);
	        
	        String analyze = res;
	        if (analyze == null) {
	            Alert alert = new Alert(Alert.AlertType.INFORMATION);
	            alert.setTitle("Export text");
	            alert.setHeaderText("Export failed");
	            //alert.setContentText("Please select the frame to export");
	            alert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
	            alert.showAndWait();
	            return;
	        }
	        FileChooser fileChooser = new FileChooser();
	        fileChooser.setTitle("Export text");
	        File filex = fileChooser.showSaveDialog(null);
	        if (file == null) {
	            Alert alert = new Alert(Alert.AlertType.ERROR);
	            alert.setTitle("Export error");
	            alert.setHeaderText("Analysis export error");
	            alert.setContentText("The export file could not be opened");
	            alert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
	            alert.showAndWait();
	            return;
	        }
	        try {
	            FileOutputStream stream = new FileOutputStream(filex);
	            stream.write(analyze.getBytes(StandardCharsets.UTF_8));
	            stream.close();
	        } catch (FileNotFoundException e) {
	            Alert alert = new Alert(Alert.AlertType.ERROR);
	            alert.setTitle("Export error");
	            alert.setHeaderText("Analysis export error");
	            alert.setContentText("The export file could not be opened");
	            alert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
	            alert.showAndWait();
	            return;
	        } catch (IOException e) {
	            Alert alert = new Alert(Alert.AlertType.ERROR);
	            alert.setTitle("Export error");
	            alert.setHeaderText("Analysis export error");
	            alert.setContentText("Analysis could not be written to file");
	            alert.getDialogPane().setMinHeight(Region.USE_PREF_SIZE);
	            alert.showAndWait();
	            return;
	        }
	        
	

    }
    
    
    
    @FXML
    public void initialize() throws AnalyzerException {
    	
    	
    }
    
    


    
    

}