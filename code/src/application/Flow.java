package application;
import pobj.analyzer.*;


public class Flow {

    private String frame;
    private String portsrc;
    private String arrow;
    private String portdest;
    private String comment;
	


	public Flow(String frame, String portsrc, String arrow, String portdest, String comment) {
		// TODO Auto-generated constructor stub
		this.frame = frame;
		this.portsrc = portsrc;
		this.arrow = arrow;
		this.portdest = portdest;
		this.comment = comment;
	}


	public String getFrame() {
		return frame;
	}



	public String getPortsrc() {
		return portsrc;
	}



	public String getArrow() {
		return arrow;
	}



	public String getPortdest() {
		return portdest;
	}



	public String getComment() {
		return comment;
	}
    

    
    
    
}