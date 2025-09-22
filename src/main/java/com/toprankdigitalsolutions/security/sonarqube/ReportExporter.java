package com.toprankdigitalsolutions.security.sonarqube;

import kong.unirest.core.JsonNode;
import kong.unirest.core.JsonResponse;
import kong.unirest.core.json.JSONArray;
import kong.unirest.core.json.JSONObject;

import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.stream.Collectors;

/**
 * Handles exporting SonarQube analysis results to CSV files
 */
public class ReportExporter {
    
    private final SonarQubeClient client;
    
    public ReportExporter(SonarQubeClient client) {
        this.client = client;
    }
    
    /**
     * Export all reports for a project
     */
    public void exportAllReports(String projectKey, String outputPath) {
        if (!client.isAvailable()) {
            System.err.println("❌ SonarQube server not available");
            return;
        }
        
        System.out.println("🔍 Starting report export for project: " + projectKey);
        System.out.println("📁 Reports will be saved to: ./reports/" + projectKey + "/");
        
        // Create project-specific reports directory
        createReportsDirectory(outputPath, projectKey);
        
        // Export issues by severity
        String[] severities = {"BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"};
        for (String severity : severities) {
            exportIssuesBySeverity(severity, outputPath, projectKey);
        }
        
        // Export security hotspots
        exportSecurityHotspots(outputPath, projectKey);
        
        System.out.println("✅ Report export completed! Check ./reports/" + projectKey + "/ for CSV files");
    }
    
    /**
     * Create the reports directory structure
     */
    private void createReportsDirectory(String basePath, String projectKey) {
        java.io.File projectReportsDir = new java.io.File(basePath + "/reports/" + projectKey);
        if (!projectReportsDir.exists()) {
            projectReportsDir.mkdirs();
            System.out.println("✅ Created project reports directory: " + projectReportsDir.getAbsolutePath());
        }
    }
    
    /**
     * Export issues for a specific severity level
     */
    private void exportIssuesBySeverity(String severity, String outputPath, String projectKey) {
        System.out.println("Fetching " + severity + " issues for project: " + projectKey);
        
        try {
            JsonResponse response = client.searchIssues(projectKey, severity);
            int responseStatus = response.getStatus();
            System.out.println("issuesSearchResponseStatus = " + responseStatus);

            if (responseStatus != 200) {
                System.err.println("❌ Failed to fetch " + severity + " issues. Response: " + response.getBody());
                return;
            }

            JsonNode responseBody = response.getBody();
            JSONArray issues = responseBody.getObject().getJSONArray("issues");
            
            System.out.println("Found " + issues.length() + " " + severity + " issues");
            
            // Convert to Issue objects and write CSV
            ArrayList<Issue> listOfIssues = convertJsonToIssues(issues);
            writeIssuesCsv(listOfIssues, severity, outputPath, projectKey);
            
        } catch (Exception e) {
            System.err.println("❌ Error fetching " + severity + " issues: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Export security hotspots
     */
    private void exportSecurityHotspots(String outputPath, String projectKey) {
        System.out.println("Fetching security hotspots for project: " + projectKey);
        
        try {
            JsonResponse response = client.searchHotspots(projectKey);
            int responseStatus = response.getStatus();
            System.out.println("hotspotsSearchResponseStatus = " + responseStatus);

            if (responseStatus != 200) {
                System.err.println("❌ Failed to fetch security hotspots. Response: " + response.getBody());
                return;
            }

            JsonNode responseBody = response.getBody();
            JSONArray hotspots = responseBody.getObject().getJSONArray("hotspots");
            
            System.out.println("Found " + hotspots.length() + " security hotspots");
            
            // Convert to Hotspot objects and write CSV
            ArrayList<Hotspot> listOfHotspots = convertJsonToHotspots(hotspots);
            writeHotspotsCsv(listOfHotspots, outputPath, projectKey);
            
        } catch (Exception e) {
            System.err.println("❌ Error fetching security hotspots: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Convert JSON array to Issue objects
     */
    private ArrayList<Issue> convertJsonToIssues(JSONArray issues) {
        ArrayList<Issue> listOfIssues = new ArrayList<>();
        
        issues.forEach(issueNode -> {
            Issue issue = new Issue();
            JSONObject jsonObject = (JSONObject) issueNode;
            
            issue.setKey(jsonObject.optString("key"));
            issue.setRule(jsonObject.optString("rule"));
            issue.setSeverity(jsonObject.optString("severity"));
            issue.setComponent(jsonObject.optString("component"));
            issue.setProject(jsonObject.optString("project"));
            issue.setLine(jsonObject.optString("line"));
            issue.setHash(jsonObject.optString("hash"));
            issue.setTextRange_startLine(jsonObject.optString("textRange_startLine"));
            issue.setTextRange_endLine(jsonObject.optString("textRange_endLine"));
            issue.setTextRange_startOffset(jsonObject.optString("textRange_startOffset"));
            issue.setTextRange_endOffset(jsonObject.optString("textRange_endOffset"));
            issue.setStatus(jsonObject.optString("status"));
            issue.setMessage(jsonObject.optString("message"));
            issue.setEffort(jsonObject.optString("effort"));
            issue.setDebt(jsonObject.optString("debt"));
            issue.setAuthor(jsonObject.optString("author"));
            issue.setCreationDate(jsonObject.optString("creationDate"));
            issue.setUpdateDate(jsonObject.optString("updateDate"));
            issue.setType(jsonObject.optString("type"));
            issue.setScope(jsonObject.optString("scope"));
            
            listOfIssues.add(issue);
        });
        
        return listOfIssues;
    }
    
    /**
     * Convert JSON array to Hotspot objects
     */
    private ArrayList<Hotspot> convertJsonToHotspots(JSONArray hotspots) {
        ArrayList<Hotspot> listOfHotspots = new ArrayList<>();
        
        hotspots.forEach(hotspotNode -> {
            Hotspot hotspot = new Hotspot();
            JSONObject jsonObject = (JSONObject) hotspotNode;
            
            hotspot.setKey(jsonObject.optString("key"));
            hotspot.setComponent(jsonObject.optString("component"));
            hotspot.setProject(jsonObject.optString("project"));
            hotspot.setSecurityCategory(jsonObject.optString("securityCategory"));
            hotspot.setVulnerabilityProbability(jsonObject.optString("vulnerabilityProbability"));
            hotspot.setStatus(jsonObject.optString("status"));
            hotspot.setLine(jsonObject.optString("line"));
            hotspot.setMessage(jsonObject.optString("message"));
            hotspot.setAuthor(jsonObject.optString("author"));
            hotspot.setCreationDate(jsonObject.optString("creationDate"));
            hotspot.setUpdateDate(jsonObject.optString("updateDate"));
            
            listOfHotspots.add(hotspot);
        });
        
        return listOfHotspots;
    }
    
    /**
     * Write issues to CSV file
     */
    private void writeIssuesCsv(ArrayList<Issue> listOfIssues, String severity, String outputPath, String projectKey) {
        try {
            String[] csvHeaders = {
                "key", "rule", "severity", "component", "project", "line", "hash",
                "textRange_startLine", "textRange_endLine", "textRange_startOffset", 
                "textRange_endOffset", "status", "message", "effort", "debt", 
                "author", "creationDate", "updateDate", "type", "scope"
            };

            String csvHeaderLine = String.join(",", csvHeaders) + System.lineSeparator();
            String recordsAsCsv = listOfIssues.stream()
                    .map(Issue::toCsvRow)
                    .collect(Collectors.joining(System.lineSeparator()));

            try (FileWriter csvFileWriter = new FileWriter(outputPath + "/reports/" + projectKey + "/" + severity + ".csv")) {
                csvFileWriter.write(csvHeaderLine);
                csvFileWriter.write(recordsAsCsv);
                System.out.println("✅ " + severity + " issues exported: " + listOfIssues.size() + " records");
            }
        } catch (IOException e) {
            System.err.println("❌ Error writing " + severity + " CSV: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Write hotspots to CSV file
     */
    private void writeHotspotsCsv(ArrayList<Hotspot> listOfHotspots, String outputPath, String projectKey) {
        try {
            String[] csvHeaders = {
                "key", "component", "project", "securityCategory", "vulnerabilityProbability",
                "status", "line", "message", "author", "creationDate", "updateDate"
            };

            String csvHeaderLine = String.join(",", csvHeaders) + System.lineSeparator();
            String recordsAsCsv = listOfHotspots.stream()
                    .map(Hotspot::toCsvRow)
                    .collect(Collectors.joining(System.lineSeparator()));

            try (FileWriter csvFileWriter = new FileWriter(outputPath + "/reports/" + projectKey + "/hotspots.csv")) {
                csvFileWriter.write(csvHeaderLine);
                csvFileWriter.write(recordsAsCsv);
                System.out.println("✅ Security hotspots exported: " + listOfHotspots.size() + " records");
            }
        } catch (IOException e) {
            System.err.println("❌ Error writing hotspots CSV: " + e.getMessage());
            e.printStackTrace();
        }
    }
}

