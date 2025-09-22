package com.toprankdigitalsolutions.security.sonarqube;

import kong.unirest.core.JsonNode;
import kong.unirest.core.JsonResponse;
import kong.unirest.core.json.JSONArray;
import kong.unirest.core.json.JSONObject;

import java.io.FileWriter;
import java.io.IOException;

/**
 * Manages SonarQube projects and authentication tokens
 */
public class ProjectManager {
    
    private final SonarQubeClient client;
    
    public ProjectManager(SonarQubeClient client) {
        this.client = client;
    }
    
    /**
     * Check if a project already exists
     */
    public boolean projectExists(String projectKey) {
        try {
            JsonResponse response = client.searchProjects(projectKey);
            if (response.getStatus() == 200) {
                JSONArray projects = response.getBody().getObject().getJSONArray("components");
                for (int i = 0; i < projects.length(); i++) {
                    JSONObject project = projects.getJSONObject(i);
                    if (projectKey.equals(project.optString("key"))) {
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Error checking if project exists: " + e.getMessage());
        }
        return false;
    }
    
    /**
     * Check if a token already exists
     */
    public boolean tokenExists(String tokenName) {
        try {
            JsonResponse response = client.searchTokens();
            if (response.getStatus() == 200) {
                JSONArray tokens = response.getBody().getObject().getJSONArray("userTokens");
                for (int i = 0; i < tokens.length(); i++) {
                    JSONObject token = tokens.getJSONObject(i);
                    if (tokenName.equals(token.optString("name"))) {
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Error checking if token exists: " + e.getMessage());
        }
        return false;
    }
    
    /**
     * Create a new project if it doesn't exist
     */
    public boolean createProjectIfNotExists(String projectName, String projectKey) {
        if (projectExists(projectKey)) {
            System.out.println("✅ Project '" + projectKey + "' already exists, skipping creation.");
            return true;
        }
        
        System.out.println("Creating new project: " + projectKey);
        JsonResponse response = client.createProject(projectName, projectKey);
        int responseCode = response.getStatus();
        System.out.println("createProjectResponseCode = " + responseCode);
        
        if (responseCode == 200) {
            System.out.println("✅ Project created successfully: " + projectKey);
            return true;
        } else {
            System.err.println("❌ Failed to create project. Response: " + response.getBody());
            return false;
        }
    }
    
    /**
     * Generate a token with automatic fallback for duplicates
     */
    public String generateToken(String projectName) {
        String tokenName = projectName + "_access_token";
        
        if (tokenExists(tokenName)) {
            System.out.println("⚠️ Token '" + tokenName + "' already exists.");
            System.out.println("🔄 Creating timestamped token instead...");
            tokenName = tokenName + "_" + System.currentTimeMillis();
        }
        
        System.out.println("Creating token: " + tokenName);
        JsonResponse response = client.generateToken(tokenName);
        int responseCode = response.getStatus();
        System.out.println("createAccessTokenResponseCode = " + responseCode);
        
        if (responseCode == 200) {
            JsonNode responseBody = response.getBody();
            String token = responseBody.getObject().get("token").toString();
            System.out.println("✅ Token created successfully: " + tokenName);
            return token;
        } else {
            System.err.println("❌ Failed to create token. Response: " + response.getBody());
            return null;
        }
    }
    
    /**
     * Save project configuration to file
     */
    public void saveConfiguration(String projectKey, String token, String filePath) {
        try (FileWriter variables = new FileWriter(filePath + "/sq_variables.config")) {
            variables.write("SQ_PROJECT_KEY=" + projectKey + System.lineSeparator());
            variables.write("SQ_ACCESS_TOKEN=" + token + System.lineSeparator());
            System.out.println("✅ Configuration saved to: " + filePath + "/sq_variables.config");
        } catch (IOException e) {
            System.err.println("❌ Failed to save configuration: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * Display all projects in a formatted table
     */
    public void listAllProjects() {
        try {
            JsonResponse response = client.getAllProjects();
            int responseStatus = response.getStatus();
            System.out.println("projectsSearchResponseStatus = " + responseStatus);

            if (responseStatus != 200) {
                System.err.println("❌ Failed to fetch projects. Response: " + response.getBody());
                return;
            }

            JsonNode responseBody = response.getBody();
            JSONArray projects = responseBody.getObject().getJSONArray("components");
            
            if (projects.length() == 0) {
                System.out.println("📝 No projects found in SonarQube");
                return;
            }
            
            System.out.println("\n📋 Found " + projects.length() + " project(s):");
            System.out.println("=" + "=".repeat(60));
            System.out.printf("%-30s | %-25s%n", "PROJECT NAME", "PROJECT KEY");
            System.out.println("-" + "-".repeat(60));
            
            for (int i = 0; i < projects.length(); i++) {
                JSONObject project = projects.getJSONObject(i);
                String name = project.optString("name", "N/A");
                String key = project.optString("key", "N/A");
                System.out.printf("%-30s | %-25s%n", 
                    name.length() > 30 ? name.substring(0, 27) + "..." : name, 
                    key.length() > 25 ? key.substring(0, 22) + "..." : key);
            }
            
            System.out.println("=" + "=".repeat(60));
            System.out.println("✅ Projects listing completed");
            
        } catch (Exception e) {
            System.err.println("❌ Error fetching projects: " + e.getMessage());
            e.printStackTrace();
        }
    }
}

