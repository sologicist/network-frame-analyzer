module FrameAnalyzer {
	exports application;
	exports pobj.analyzer;

	requires java.desktop;
	requires javafx.base;
	requires javafx.controls;
	requires javafx.fxml;
	requires javafx.graphics;
	opens application;
}