package com.goecfx.security.sonarqube;

import kong.unirest.JsonNode;
import kong.unirest.JsonResponse;
import kong.unirest.Unirest;
import kong.unirest.json.JSONArray;
import kong.unirest.json.JSONObject;

import java.io.FileWriter;
import java.util.ArrayList;
import java.util.stream.Collectors;

public class ProjectScanner {
    private static void orchestrateScanning(String initialPath, String projectName, String projectKey) {
        // Create the project

        JsonResponse createProjectResponse =
                (JsonResponse)
                        Unirest.post("http://localhost:9000/api/projects/create")
                                .header("Content-Type", "application/x-www-form-urlencoded")
                                .header("Authorization", ProjectScannerConstants.AUTHENTICATION_HEADER_VALUE)
                                .body("name=" + projectName + "&project=" + projectKey)
                                .asJson();

        int createProjectResponseCode = createProjectResponse.getStatus();
        System.out.println("createProjectResponseCode = " + createProjectResponseCode);

        // Get the projects

        JsonResponse getProjectsResponse =
                (JsonResponse)
                        Unirest.get("http://localhost:9000/api/projects/search")
                                .header("Authorization", ProjectScannerConstants.AUTHENTICATION_HEADER_VALUE)
                                .asJson();

        int getProjectsResponseCode = getProjectsResponse.getStatus();
        System.out.println("getProjectsResponseCode = " + getProjectsResponseCode);

        // Create the user token

        String tokenName = projectName + "_access_token";

        JsonResponse createAccessTokenResponse =
                (JsonResponse)
                        Unirest.post("http://localhost:9000/api/user_tokens/generate")
                                .header("Content-Type", "application/x-www-form-urlencoded")
                                .header("Authorization", ProjectScannerConstants.AUTHENTICATION_HEADER_VALUE)
                                .body("name=" + tokenName)
                                .asJson();

        int createAccessTokenResponseCode = createAccessTokenResponse.getStatus();
        System.out.println("createAccessTokenResponseCode = " + createAccessTokenResponseCode);

        JsonNode createAccessTokenResponseBody = createAccessTokenResponse.getBody();

        String token = createAccessTokenResponseBody.getObject().get("token").toString();

        try {
            FileWriter variables = new FileWriter(initialPath + "/" + "sq_variables.config");
            variables.write("SQ_PROJECT_KEY=" + projectKey + System.lineSeparator());
            variables.write("SQ_ACCESS_TOKEN=" + token + System.lineSeparator());

            variables.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void writeIssuesCsv(ArrayList<Issue> listOfIssues, String severity, String initialPath) {
        try {
            FileWriter csvFileWriter = new FileWriter(initialPath + "/reports/" + severity + ".csv");

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
            csvFileWriter.write(csvHeaderLine);

            String recordsAsCsv =
                    listOfIssues.stream()
                            .map(Issue::toCsvRow)
                            .collect(Collectors.joining(System.lineSeparator()));

            csvFileWriter.write(recordsAsCsv);

            csvFileWriter.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void processJsonArrayOfIssues(JSONArray issues, String severity, String initialPath) {
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

        ProjectScanner.writeIssuesCsv(listOfIssues, severity, initialPath);
    }

    private static void writeHotspotsCsv(ArrayList<Hotspot> listOfHotspots, String initialPath) {
        try {
            FileWriter csvFileWriter = new FileWriter(initialPath + "/reports/hotspots.csv");

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
            csvFileWriter.write(csvHeaderLine);

            String recordsAsCsv =
                    listOfHotspots.stream()
                        .map(Hotspot::toCsvRow)
                        .collect(Collectors.joining(System.lineSeparator()));

            csvFileWriter.write(recordsAsCsv);

            csvFileWriter.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void processJsonArrayOfHotspots(JSONArray hotspots, String initialPath) {
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

        ProjectScanner.writeHotspotsCsv(listOfHotspots, initialPath);
    }

    private static void parseReport(String severity, String initialPath, String projectKey) {
        JsonResponse issuesSearchResponse =
                (JsonResponse)
                        Unirest.get("http://localhost:9000/api/issues/search")
                                .header("Content-Type", "application/x-www-form-urlencoded")
                                .header("Authorization", ProjectScannerConstants.AUTHENTICATION_HEADER_VALUE)
                                .queryString("project", projectKey)
                                .queryString("severities", severity)
                                .asJson();

        int issuesSearchResponseStatus = issuesSearchResponse.getStatus();
        System.out.println("issuesSearchResponseStatus = " + issuesSearchResponseStatus);

        JsonNode issuesSearchResponseBody = issuesSearchResponse.getBody();

        JSONArray issues = issuesSearchResponseBody.getObject().getJSONArray("issues");

        ProjectScanner.processJsonArrayOfIssues(issues, severity, initialPath);
    }

    private static void getSecurityHotspots(String initialPath, String projectKey) {
        JsonResponse hotspotsSearchResponse =
                (JsonResponse)
                        Unirest.get("http://localhost:9000/api/hotspots/search")
                                .header("Content-Type", "application/x-www-form-urlencoded")
                                .header("Authorization", ProjectScannerConstants.AUTHENTICATION_HEADER_VALUE)
                                .queryString("projectKey", projectKey)
                                .asJson();

        int hotspotsSearchResponseStatus = hotspotsSearchResponse.getStatus();
        System.out.println("hotspotsSearchResponseStatus = " + hotspotsSearchResponseStatus);

        JsonNode hotspotsSearchResponseBody = hotspotsSearchResponse.getBody();

        JSONArray hotspots = hotspotsSearchResponseBody.getObject().getJSONArray("hotspots");

        ProjectScanner.processJsonArrayOfHotspots(hotspots, initialPath);
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

        if (mode.equals(ProjectScannerConstants.PARSE_REPORT_MODE)) {
            projectKey = args.length > 2 ? args[2] : "";

            ProjectScanner.parseReport("BLOCKER", initialPath, projectKey);
            ProjectScanner.parseReport("CRITICAL", initialPath, projectKey);
            ProjectScanner.parseReport("MAJOR", initialPath, projectKey);
            ProjectScanner.parseReport("MINOR", initialPath, projectKey);
            ProjectScanner.parseReport("INFO", initialPath, projectKey);

            ProjectScanner.getSecurityHotspots(initialPath, projectKey);
        }
    }
}
