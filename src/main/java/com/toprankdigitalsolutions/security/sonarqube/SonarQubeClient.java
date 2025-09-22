package com.toprankdigitalsolutions.security.sonarqube;

import kong.unirest.core.JsonNode;
import kong.unirest.core.JsonResponse;
import kong.unirest.core.Unirest;
import kong.unirest.core.json.JSONArray;

/**
 * Handles all communication with SonarQube REST API
 */
public class SonarQubeClient {
    
    private String baseUrl;
    
    public SonarQubeClient() {
        this.baseUrl = detectSonarQubeUrl();
    }
    
    public SonarQubeClient(String baseUrl) {
        this.baseUrl = baseUrl;
    }
    
    /**
     * Auto-detect SonarQube URL by trying common ports
     */
    private String detectSonarQubeUrl() {
        // Try port 9001 first, then 9000
        String[] urls = {"http://localhost:9001", "http://localhost:9000"};
        
        for (String url : urls) {
            try {
                JsonResponse response = (JsonResponse) Unirest.get(url + "/api/system/status")
                        .header("Authorization", ProjectScannerConstants.AUTHENTICATION_HEADER_VALUE)
                        .asJson();
                if (response.getStatus() == 200) {
                    System.out.println("✅ SonarQube found at: " + url);
                    return url;
                }
            } catch (Exception e) {
                // Try next URL
            }
        }
        
        System.err.println("❌ SonarQube not accessible on ports 9000 or 9001");
        System.err.println("💡 Make sure the SonarQube container is running");
        return null;
    }
    
    public boolean isAvailable() {
        return baseUrl != null;
    }
    
    public String getBaseUrl() {
        return baseUrl;
    }
    
    /**
     * Create a new project in SonarQube
     */
    public JsonResponse createProject(String projectName, String projectKey) {
        return (JsonResponse) Unirest.post(baseUrl + "/api/projects/create")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Authorization", ProjectScannerConstants.AUTHENTICATION_HEADER_VALUE)
                .body("name=" + projectName + "&project=" + projectKey)
                .asJson();
    }
    
    /**
     * Search for projects
     */
    public JsonResponse searchProjects(String query) {
        return (JsonResponse) Unirest.get(baseUrl + "/api/projects/search")
                .header("Authorization", ProjectScannerConstants.AUTHENTICATION_HEADER_VALUE)
                .queryString("q", query)
                .asJson();
    }
    
    /**
     * Search all projects
     */
    public JsonResponse getAllProjects() {
        return (JsonResponse) Unirest.get(baseUrl + "/api/projects/search")
                .header("Authorization", ProjectScannerConstants.AUTHENTICATION_HEADER_VALUE)
                .queryString("ps", "100")
                .asJson();
    }
    
    /**
     * Generate a user token
     */
    public JsonResponse generateToken(String tokenName) {
        return (JsonResponse) Unirest.post(baseUrl + "/api/user_tokens/generate")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Authorization", ProjectScannerConstants.AUTHENTICATION_HEADER_VALUE)
                .body("name=" + tokenName)
                .asJson();
    }
    
    /**
     * Search user tokens
     */
    public JsonResponse searchTokens() {
        return (JsonResponse) Unirest.get(baseUrl + "/api/user_tokens/search")
                .header("Authorization", ProjectScannerConstants.AUTHENTICATION_HEADER_VALUE)
                .asJson();
    }
    
    /**
     * Search for issues by project and severity
     */
    public JsonResponse searchIssues(String projectKey, String severity) {
        return (JsonResponse) Unirest.get(baseUrl + "/api/issues/search")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Authorization", ProjectScannerConstants.AUTHENTICATION_HEADER_VALUE)
                .queryString("project", projectKey)
                .queryString("severities", severity)
                .asJson();
    }
    
    /**
     * Search for security hotspots by project
     */
    public JsonResponse searchHotspots(String projectKey) {
        return (JsonResponse) Unirest.get(baseUrl + "/api/hotspots/search")
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Authorization", ProjectScannerConstants.AUTHENTICATION_HEADER_VALUE)
                .queryString("projectKey", projectKey)
                .asJson();
    }
}

