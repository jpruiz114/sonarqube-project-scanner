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
    /** "YWRtaW46YWRtaW4"= = admin:admin */
    public static String authHeaderValue = "Basic YWRtaW46YWRtaW4=";

    public static String projectName = "security";
    public static String projectKey = "security-project-key";

    private static void orchestrateScanning(String initialPath) {
        // Create the project

        JsonResponse createProjectResponse =
                (JsonResponse)
                        Unirest.post("http://localhost:9000/api/projects/create")
                                .header("Content-Type", "application/x-www-form-urlencoded")
                                .header("Authorization", authHeaderValue)
                                .body("name=" + projectName + "&project=" + projectKey)
                                .asJson();

        int createProjectResponseCode = createProjectResponse.getStatus();
        System.out.println("createProjectResponseCode = " + createProjectResponseCode);

        // Get the projects

        JsonResponse getProjectsResponse =
                (JsonResponse)
                        Unirest.get("http://localhost:9000/api/projects/search")
                                .header("Authorization", authHeaderValue)
                                .asJson();

        int getProjectsResponseCode = getProjectsResponse.getStatus();
        System.out.println("getProjectsResponseCode = " + getProjectsResponseCode);

        // Create the user token

        JsonResponse createAccessTokenResponse =
                (JsonResponse)
                        Unirest.post("http://localhost:9000/api/user_tokens/generate")
                                .header("Content-Type", "application/x-www-form-urlencoded")
                                .header("Authorization", authHeaderValue)
                                .body("name=admin-access-token")
                                .asJson();

        int createAccessTokenResponseCode = createAccessTokenResponse.getStatus();
        System.out.println("createAccessTokenResponseCode = " + createAccessTokenResponseCode);

        JsonNode createAccessTokenResponseBody = createAccessTokenResponse.getBody();

        String token = createAccessTokenResponseBody.getObject().get("token").toString();
        System.out.println("token = " + token);

        try {
            FileWriter variables = new FileWriter(initialPath + "/" + "sq_variables.config");
            variables.write("SQ_PROJECT_KEY=" + projectKey + System.lineSeparator());
            variables.write("SQ_ACCESS_TOKEN=" + token + System.lineSeparator());

            variables.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void writeCsv(ArrayList<Issue> listOfIssues, String severity, String initialPath) {
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

    private static void processJsonArrayOfIssues(
            JSONArray issues, String severity, String initialPath) {
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
                });

        ProjectScanner.writeCsv(listOfIssues, severity, initialPath);
    }

    private static void parseReport(String severity, String initialPath) {
        JsonResponse issuesSearchResponse =
                (JsonResponse)
                        Unirest.get("http://localhost:9000/api/issues/search")
                                .header("Content-Type", "application/x-www-form-urlencoded")
                                .header("Authorization", authHeaderValue)
                                .queryString("project", projectKey)
                                .queryString("severities", severity)
                                .asJson();

        int issuesSearchResponseStatus = issuesSearchResponse.getStatus();
        System.out.println("issuesSearchResponseStatus = " + issuesSearchResponseStatus);

        JsonNode issuesSearchResponseBody = issuesSearchResponse.getBody();

        JSONArray issues = issuesSearchResponseBody.getObject().getJSONArray("issues");

        ProjectScanner.processJsonArrayOfIssues(issues, severity, initialPath);
    }

    public static void main(String[] args) {
        String mode = "";

        if (args.length > 0) {
            mode = args[0];
        }

        String initialPath = "";

        if (args.length > 1) {
            initialPath = args[1];
        }

        if (mode.equals("orchestrateScanning")) {
            ProjectScanner.orchestrateScanning(initialPath);
        }

        if (mode.equals("parseReport")) {
            ProjectScanner.parseReport("BLOCKER", initialPath);
            ProjectScanner.parseReport("CRITICAL", initialPath);
            ProjectScanner.parseReport("MAJOR", initialPath);
            ProjectScanner.parseReport("MINOR", initialPath);
            ProjectScanner.parseReport("INFO", initialPath);
        }
    }
}
