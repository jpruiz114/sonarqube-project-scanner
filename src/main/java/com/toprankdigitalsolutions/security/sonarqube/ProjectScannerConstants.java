package com.toprankdigitalsolutions.security.sonarqube;

public class ProjectScannerConstants {
    public static final String ORCHESTRATE_SCANNING_MODE = "orchestrateScanning";
    public static final String RUN_SCAN_MODE = "runScan";
    public static final String PARSE_REPORT_MODE = "parseReport";
    public static final String LIST_PROJECTS_MODE = "listProjects";
    // This is the base64 encode of admin:admin, the default username:password of SonarQube
    public static final String AUTHENTICATION_HEADER_VALUE = "Basic YWRtaW46YWRtaW4=";
}
