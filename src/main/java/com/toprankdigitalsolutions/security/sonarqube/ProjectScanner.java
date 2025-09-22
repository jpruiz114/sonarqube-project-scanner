package com.toprankdigitalsolutions.security.sonarqube;

import kong.unirest.core.JsonNode;
import kong.unirest.core.JsonResponse;
import kong.unirest.core.Unirest;
import kong.unirest.core.json.JSONArray;
import kong.unirest.core.json.JSONObject;

import java.io.FileWriter;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Properties;
import java.util.stream.Collectors;

public class ProjectScanner {
    
    private static boolean projectExists(String projectKey) {
        try {
            JsonResponse response = (JsonResponse) Unirest.get("http://localhost:9001/api/projects/search")
                    .header("Authorization", ProjectScannerConstants.AUTHENTICATION_HEADER_VALUE)
                    .queryString("q", projectKey)
                    .asJson();

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
    
    private static boolean tokenExists(String tokenName) {
        try {
            JsonResponse response = (JsonResponse) Unirest.get("http://localhost:9001/api/user_tokens/search")
                    .header("Authorization", ProjectScannerConstants.AUTHENTICATION_HEADER_VALUE)
                    .asJson();

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

    private static void orchestrateScanning(String initialPath, String projectName, String projectKey) {
        // Check if project already exists
        if (projectExists(projectKey)) {
            System.out.println("✅ Project '" + projectKey + "' already exists, skipping creation.");
        } else {
            System.out.println("Creating new project: " + projectKey);
            JsonResponse createProjectResponse =
                    (JsonResponse)
                            Unirest.post("http://localhost:9001/api/projects/create")
                                    .header("Content-Type", "application/x-www-form-urlencoded")
                                    .header("Authorization", ProjectScannerConstants.AUTHENTICATION_HEADER_VALUE)
                                    .body("name=" + projectName + "&project=" + projectKey)
                                    .asJson();

            int createProjectResponseCode = createProjectResponse.getStatus();
            System.out.println("createProjectResponseCode = " + createProjectResponseCode);
            
            if (createProjectResponseCode != 200) {
                System.err.println("❌ Failed to create project. Response: " + createProjectResponse.getBody());
                return;
            }
        }

        // Get the projects

        JsonResponse getProjectsResponse =
                (JsonResponse)
                        Unirest.get("http://localhost:9001/api/projects/search")
                                .header("Authorization", ProjectScannerConstants.AUTHENTICATION_HEADER_VALUE)
                                .asJson();

        int getProjectsResponseCode = getProjectsResponse.getStatus();
        System.out.println("getProjectsResponseCode = " + getProjectsResponseCode);

        // Create the user token
        String tokenName = projectName + "_access_token";
        String token = null;

        if (tokenExists(tokenName)) {
            System.out.println("⚠️ Token '" + tokenName + "' already exists. Cannot retrieve existing token value for security reasons.");
            System.out.println("💡 Options:");
            System.out.println("   1. Delete the existing token in SonarQube web interface");
            System.out.println("   2. Use a different project name");
            System.out.println("   3. Manually retrieve the token from your records");
            
            // Create a timestamped token name as fallback
            String timestampedTokenName = tokenName + "_" + System.currentTimeMillis();
            System.out.println("🔄 Creating new token with unique name: " + timestampedTokenName);
            
            JsonResponse createAccessTokenResponse =
                    (JsonResponse)
                            Unirest.post("http://localhost:9001/api/user_tokens/generate")
                                    .header("Content-Type", "application/x-www-form-urlencoded")
                                    .header("Authorization", ProjectScannerConstants.AUTHENTICATION_HEADER_VALUE)
                                    .body("name=" + timestampedTokenName)
                                    .asJson();

            int createAccessTokenResponseCode = createAccessTokenResponse.getStatus();
            System.out.println("createAccessTokenResponseCode = " + createAccessTokenResponseCode);
            
            if (createAccessTokenResponseCode == 200) {
                JsonNode createAccessTokenResponseBody = createAccessTokenResponse.getBody();
                token = createAccessTokenResponseBody.getObject().get("token").toString();
                System.out.println("✅ New token created: " + timestampedTokenName);
            } else {
                System.err.println("❌ Failed to create fallback token. Response: " + createAccessTokenResponse.getBody());
                return;
            }
        } else {
            System.out.println("Creating new token: " + tokenName);
            JsonResponse createAccessTokenResponse =
                    (JsonResponse)
                            Unirest.post("http://localhost:9001/api/user_tokens/generate")
                                    .header("Content-Type", "application/x-www-form-urlencoded")
                                    .header("Authorization", ProjectScannerConstants.AUTHENTICATION_HEADER_VALUE)
                                    .body("name=" + tokenName)
                                    .asJson();

            int createAccessTokenResponseCode = createAccessTokenResponse.getStatus();
            System.out.println("createAccessTokenResponseCode = " + createAccessTokenResponseCode);

            if (createAccessTokenResponseCode == 200) {
                JsonNode createAccessTokenResponseBody = createAccessTokenResponse.getBody();
                token = createAccessTokenResponseBody.getObject().get("token").toString();
                System.out.println("✅ Token created successfully: " + tokenName);
            } else {
                System.err.println("❌ Failed to create token. Response: " + createAccessTokenResponse.getBody());
                return;
            }
        }
        
        if (token == null) {
            System.err.println("❌ No token available. Cannot proceed.");
            return;
        }

        try (FileWriter variables = new FileWriter(initialPath + "/" + "sq_variables.config")) {
            variables.write("SQ_PROJECT_KEY=" + projectKey + System.lineSeparator());
            variables.write("SQ_ACCESS_TOKEN=" + token + System.lineSeparator());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void writeIssuesCsv(ArrayList<Issue> listOfIssues, String severity, String initialPath, String projectKey) {
        try {
            // Create project-specific reports directory if it doesn't exist
            java.io.File projectReportsDir = new java.io.File(initialPath + "/reports/" + projectKey);
            if (!projectReportsDir.exists()) {
                projectReportsDir.mkdirs();
                System.out.println("✅ Created project reports directory: " + projectReportsDir.getAbsolutePath());
            }
            
            String[] csvHeaders = {
                "key",
                "rule",
                "severity",
                "component",
                "project",
                "line",
                "hash",
                "textRange_startLine",
                "textRange_endLine",
                "textRange_startOffset",
                "textRange_endOffset",
                "status",
                "message",
                "effort",
                "debt",
                "author",
                "creationDate",
                "updateDate",
                "type",
                "scope"
            };

            String csvHeaderLine = String.join(",", csvHeaders) + System.lineSeparator();
            String recordsAsCsv = listOfIssues.stream()
                    .map(Issue::toCsvRow)
                    .collect(Collectors.joining(System.lineSeparator()));

            try (FileWriter csvFileWriter = new FileWriter(initialPath + "/reports/" + projectKey + "/" + severity + ".csv")) {
                csvFileWriter.write(csvHeaderLine);
                csvFileWriter.write(recordsAsCsv);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void processJsonArrayOfIssues(JSONArray issues, String severity, String initialPath, String projectKey) {
        ArrayList<Issue> listOfIssues = new ArrayList<>();

        issues.forEach(
            issueNode -> {
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
            }
        );

        ProjectScanner.writeIssuesCsv(listOfIssues, severity, initialPath, projectKey);
    }

    private static void writeHotspotsCsv(ArrayList<Hotspot> listOfHotspots, String initialPath, String projectKey) {
        try {
            // Create project-specific reports directory if it doesn't exist
            java.io.File projectReportsDir = new java.io.File(initialPath + "/reports/" + projectKey);
            if (!projectReportsDir.exists()) {
                projectReportsDir.mkdirs();
                System.out.println("✅ Created project reports directory: " + projectReportsDir.getAbsolutePath());
            }
            
            String[] csvHeaders = {
                "key",
                "component",
                "project",
                "securityCategory",
                "vulnerabilityProbability",
                "status",
                "line",
                "message",
                "author",
                "creationDate",
                "updateDate"
            };

            String csvHeaderLine = String.join(",", csvHeaders) + System.lineSeparator();
            String recordsAsCsv = listOfHotspots.stream()
                    .map(Hotspot::toCsvRow)
                    .collect(Collectors.joining(System.lineSeparator()));

            try (FileWriter csvFileWriter = new FileWriter(initialPath + "/reports/" + projectKey + "/hotspots.csv")) {
                csvFileWriter.write(csvHeaderLine);
                csvFileWriter.write(recordsAsCsv);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void processJsonArrayOfHotspots(JSONArray hotspots, String initialPath, String projectKey) {
        ArrayList<Hotspot> listOfHotspots = new ArrayList<>();

        hotspots.forEach(
            hotspotNode -> {
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
            }
        );

        ProjectScanner.writeHotspotsCsv(listOfHotspots, initialPath, projectKey);
    }

    private static String getSonarQubeUrl() {
        // Try port 9001 first, then 9000
        try {
            JsonResponse response = (JsonResponse) Unirest.get("http://localhost:9001/api/system/status")
                    .header("Authorization", ProjectScannerConstants.AUTHENTICATION_HEADER_VALUE)
                    .asJson();
            if (response.getStatus() == 200) {
                System.out.println("✅ SonarQube found on port 9001");
                return "http://localhost:9001";
            }
        } catch (Exception e) {
            // Try port 9000
        }
        
        try {
            JsonResponse response = (JsonResponse) Unirest.get("http://localhost:9000/api/system/status")
                    .header("Authorization", ProjectScannerConstants.AUTHENTICATION_HEADER_VALUE)
                    .asJson();
            if (response.getStatus() == 200) {
                System.out.println("✅ SonarQube found on port 9000");
                return "http://localhost:9000";
            }
        } catch (Exception e) {
            // SonarQube not accessible
        }
        
        System.err.println("❌ SonarQube not accessible on ports 9000 or 9001");
        System.err.println("💡 Make sure the SonarQube container is running");
        return null;
    }

    private static void parseReport(String severity, String initialPath, String projectKey) {
        String sonarQubeUrl = getSonarQubeUrl();
        if (sonarQubeUrl == null) {
            return;
        }
        
        System.out.println("Fetching " + severity + " issues for project: " + projectKey);
        
        try {
            JsonResponse issuesSearchResponse =
                    (JsonResponse)
                            Unirest.get(sonarQubeUrl + "/api/issues/search")
                                    .header("Content-Type", "application/x-www-form-urlencoded")
                                    .header("Authorization", ProjectScannerConstants.AUTHENTICATION_HEADER_VALUE)
                                    .queryString("project", projectKey)
                                    .queryString("severities", severity)
                                    .asJson();

            int issuesSearchResponseStatus = issuesSearchResponse.getStatus();
            System.out.println("issuesSearchResponseStatus = " + issuesSearchResponseStatus);

            if (issuesSearchResponseStatus != 200) {
                System.err.println("❌ Failed to fetch " + severity + " issues. Response: " + issuesSearchResponse.getBody());
                return;
            }

            JsonNode issuesSearchResponseBody = issuesSearchResponse.getBody();
            JSONArray issues = issuesSearchResponseBody.getObject().getJSONArray("issues");
            
            System.out.println("Found " + issues.length() + " " + severity + " issues");
            ProjectScanner.processJsonArrayOfIssues(issues, severity, initialPath, projectKey);
            
        } catch (Exception e) {
            System.err.println("❌ Error fetching " + severity + " issues: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void getSecurityHotspots(String initialPath, String projectKey) {
        String sonarQubeUrl = getSonarQubeUrl();
        if (sonarQubeUrl == null) {
            return;
        }
        
        System.out.println("Fetching security hotspots for project: " + projectKey);
        
        try {
            JsonResponse hotspotsSearchResponse =
                    (JsonResponse)
                            Unirest.get(sonarQubeUrl + "/api/hotspots/search")
                                    .header("Content-Type", "application/x-www-form-urlencoded")
                                    .header("Authorization", ProjectScannerConstants.AUTHENTICATION_HEADER_VALUE)
                                    .queryString("projectKey", projectKey)
                                    .asJson();

            int hotspotsSearchResponseStatus = hotspotsSearchResponse.getStatus();
            System.out.println("hotspotsSearchResponseStatus = " + hotspotsSearchResponseStatus);

            if (hotspotsSearchResponseStatus != 200) {
                System.err.println("❌ Failed to fetch security hotspots. Response: " + hotspotsSearchResponse.getBody());
                return;
            }

            JsonNode hotspotsSearchResponseBody = hotspotsSearchResponse.getBody();
            JSONArray hotspots = hotspotsSearchResponseBody.getObject().getJSONArray("hotspots");
            
            System.out.println("Found " + hotspots.length() + " security hotspots");
            ProjectScanner.processJsonArrayOfHotspots(hotspots, initialPath, projectKey);
            
        } catch (Exception e) {
            System.err.println("❌ Error fetching security hotspots: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void listProjects() {
        String sonarQubeUrl = getSonarQubeUrl();
        if (sonarQubeUrl == null) {
            return;
        }
        
        System.out.println("🔍 Fetching all projects from SonarQube...");
        
        try {
            JsonResponse projectsResponse = (JsonResponse) Unirest.get(sonarQubeUrl + "/api/projects/search")
                    .header("Authorization", ProjectScannerConstants.AUTHENTICATION_HEADER_VALUE)
                    .queryString("ps", "100") // Get up to 100 projects
                    .asJson();

            int responseStatus = projectsResponse.getStatus();
            System.out.println("projectsSearchResponseStatus = " + responseStatus);

            if (responseStatus != 200) {
                System.err.println("❌ Failed to fetch projects. Response: " + projectsResponse.getBody());
                return;
            }

            JsonNode responseBody = projectsResponse.getBody();
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

    private static void runScan(String projectPath) {
        System.out.println("Running SonarQube scan for project at: " + projectPath);
        
        try {
            // Read configuration file generated by orchestrateScanning
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
            
            String projectKey = config.getProperty("SQ_PROJECT_KEY");
            String accessToken = config.getProperty("SQ_ACCESS_TOKEN");
            
            if (projectKey == null || accessToken == null) {
                System.err.println("Error: Missing project key or access token. Run orchestrateScanning first.");
                return;
            }
            
            System.out.println("Project Key: " + projectKey);
            System.out.println("Token: " + (accessToken.length() > 10 ? accessToken.substring(0, 10) + "..." : accessToken));
            
            // Build sonar-scanner command with proper permissions
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
            
            // Only add test configuration if test directory exists
            try {
                ProcessBuilder testCheck = new ProcessBuilder("docker", "exec", "sonarqube-scanner", "test", "-d", "/workspace/src/test/java");
                Process testProcess = testCheck.start();
                if (testProcess.waitFor() == 0) {
                    command.add("-Dsonar.tests=src/test/java");
                    System.out.println("✅ Test directory found, including in scan");
                } else {
                    System.out.println("ℹ️ No test directory found, scanning main sources only");
                }
            } catch (Exception e) {
                System.out.println("ℹ️ Could not check test directory, scanning main sources only");
            }
            
            // Only add binaries if they exist
            try {
                ProcessBuilder binariesCheck = new ProcessBuilder("docker", "exec", "sonarqube-scanner", "test", "-d", "/workspace/build/classes/java/main");
                Process binariesProcess = binariesCheck.start();
                if (binariesProcess.waitFor() == 0) {
                    command.add("-Dsonar.java.binaries=build/classes/java/main");
                    System.out.println("✅ Compiled classes found, including in scan");
                } else {
                    System.out.println("ℹ️ No compiled classes found, analyzing source only");
                }
            } catch (Exception e) {
                System.out.println("ℹ️ Could not check compiled classes, analyzing source only");
            }
            
            command.add("-Dsonar.host.url=http://localhost:9000");
            command.add("-Dsonar.token=" + accessToken);
            
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
            } else {
                System.err.println("❌ SonarQube scan failed with exit code: " + exitCode);
            }
            
        } catch (IOException | InterruptedException e) {
            System.err.println("Error running scan: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        String mode;
        String initialPath;
        String projectName;
        String projectKey;

        mode = args.length > 0 ? args[0] : "";
        initialPath = args.length > 1 ? args[1] : "";

        if (mode.equals(ProjectScannerConstants.ORCHESTRATE_SCANNING_MODE)) {
            projectName = args.length > 2 ? args[2] : "";
            projectKey = args.length > 3 ? args[3] : "";

            ProjectScanner.orchestrateScanning(initialPath, projectName, projectKey);
        }
        
        if (mode.equals(ProjectScannerConstants.RUN_SCAN_MODE)) {
            ProjectScanner.runScan(initialPath);
        }
        
        if (mode.equals(ProjectScannerConstants.LIST_PROJECTS_MODE)) {
            ProjectScanner.listProjects();
        }

        if (mode.equals(ProjectScannerConstants.PARSE_REPORT_MODE)) {
            projectKey = args.length > 1 ? args[1] : "";
            
            if (projectKey.isEmpty()) {
                System.err.println("❌ Project key is required for parseReport mode");
                System.err.println("Usage: java -jar fat.jar parseReport <project_key>");
                return;
            }

            System.out.println("🔍 Starting report parsing for project: " + projectKey);
            System.out.println("📁 Reports will be saved to: ./reports/" + projectKey + "/");
            
            String currentDir = System.getProperty("user.dir");
            
            ProjectScanner.parseReport("BLOCKER", currentDir, projectKey);
            ProjectScanner.parseReport("CRITICAL", currentDir, projectKey);
            ProjectScanner.parseReport("MAJOR", currentDir, projectKey);
            ProjectScanner.parseReport("MINOR", currentDir, projectKey);
            ProjectScanner.parseReport("INFO", currentDir, projectKey);

            ProjectScanner.getSecurityHotspots(currentDir, projectKey);
            
            System.out.println("✅ Report parsing completed! Check ./reports/" + projectKey + "/ for CSV files");
        }
    }
}
