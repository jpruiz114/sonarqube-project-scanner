package com.toprankdigitalsolutions.security.sonarqube;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Properties;

/**
 * Handles execution of SonarQube scanner via Docker
 */
public class ScannerExecutor {
    
    private final SonarQubeClient client;
    
    public ScannerExecutor(SonarQubeClient client) {
        this.client = client;
    }
    
    /**
     * Execute SonarQube scan for a project
     */
    public boolean runScan(String projectPath) {
        System.out.println("Running SonarQube scan for project at: " + projectPath);
        
        if (!client.isAvailable()) {
            System.err.println("❌ SonarQube server not available");
            return false;
        }
        
        try {
            // Read configuration file
            Properties config = loadConfiguration(projectPath);
            String projectKey = config.getProperty("SQ_PROJECT_KEY");
            String accessToken = config.getProperty("SQ_ACCESS_TOKEN");
            
            if (projectKey == null || accessToken == null) {
                System.err.println("❌ Missing project key or access token. Run orchestrateScanning first.");
                return false;
            }
            
            System.out.println("Project Key: " + projectKey);
            System.out.println("Token: " + (accessToken.length() > 10 ? accessToken.substring(0, 10) + "..." : accessToken));
            
            // Build scanner command
            ArrayList<String> command = buildScannerCommand(projectKey, accessToken);
            
            // Execute scan
            return executeScannerCommand(command, projectPath);
            
        } catch (IOException | InterruptedException e) {
            System.err.println("Error running scan: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    
    /**
     * Load configuration from sq_variables.config file
     */
    private Properties loadConfiguration(String projectPath) throws IOException {
        Properties config = new Properties();
        try (BufferedReader reader = new BufferedReader(new FileReader(projectPath + "/sq_variables.config"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("=")) {
                    String[] parts = line.split("=", 2);
                    config.setProperty(parts[0].trim(), parts[1].trim());
                }
            }
        }
        return config;
    }
    
    /**
     * Build the scanner command with intelligent path detection
     */
    private ArrayList<String> buildScannerCommand(String projectKey, String accessToken) {
        ArrayList<String> command = new ArrayList<>();
        command.add("docker");
        command.add("exec");
        command.add("-u");
        command.add("root");
        command.add("-e");
        command.add("SONAR_USER_HOME=/tmp/.sonar");
        command.add("-w");
        command.add("/workspace");
        command.add("sonarqube-scanner");
        command.add("sonar-scanner");
        command.add("-Dsonar.projectKey=" + projectKey);
        command.add("-Dsonar.sources=src/main/java");
        
        // Check for test directory
        if (directoryExists("/workspace/src/test/java")) {
            command.add("-Dsonar.tests=src/test/java");
            System.out.println("✅ Test directory found, including in scan");
        } else {
            System.out.println("ℹ️ No test directory found, scanning main sources only");
        }
        
        // Check for compiled classes
        if (directoryExists("/workspace/build/classes/java/main")) {
            command.add("-Dsonar.java.binaries=build/classes/java/main");
            System.out.println("✅ Compiled classes found, including in scan");
        } else {
            System.out.println("ℹ️ No compiled classes found, analyzing source only");
        }
        
        command.add("-Dsonar.host.url=" + client.getBaseUrl().replace("9001", "9000")); // Internal port
        command.add("-Dsonar.token=" + accessToken);
        
        return command;
    }
    
    /**
     * Check if a directory exists in the container
     */
    private boolean directoryExists(String path) {
        try {
            ProcessBuilder testCheck = new ProcessBuilder("docker", "exec", "sonarqube-scanner", "test", "-d", path);
            Process testProcess = testCheck.start();
            return testProcess.waitFor() == 0;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Execute the scanner command and stream output
     */
    private boolean executeScannerCommand(ArrayList<String> command, String projectPath) throws IOException, InterruptedException {
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.directory(new java.io.File(projectPath));
        processBuilder.redirectErrorStream(true);
        
        System.out.println("Executing: " + String.join(" ", processBuilder.command()));
        
        // Start the process
        Process process = processBuilder.start();
        
        // Read and display output
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
        }
        
        // Wait for completion
        int exitCode = process.waitFor();
        System.out.println("Scan completed with exit code: " + exitCode);
        
        if (exitCode == 0) {
            System.out.println("✅ SonarQube scan completed successfully!");
            return true;
        } else {
            System.err.println("❌ SonarQube scan failed with exit code: " + exitCode);
            return false;
        }
    }
}

