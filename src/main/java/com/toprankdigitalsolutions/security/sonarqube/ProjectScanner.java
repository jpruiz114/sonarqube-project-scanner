package com.toprankdigitalsolutions.security.sonarqube;

/**
 * Main application class that orchestrates SonarQube project scanning workflow
 */
public class ProjectScanner {

    public static void main(String[] args) {
        if (args.length == 0) {
            printUsage();
            return;
        }

        String mode = args[0];
        
        // Initialize SonarQube client
        SonarQubeClient client = new SonarQubeClient();
        
        switch (mode) {
            case ProjectScannerConstants.LIST_PROJECTS_MODE:
                handleListProjects(client);
                break;
                
            case ProjectScannerConstants.ORCHESTRATE_SCANNING_MODE:
                handleOrchestrateScanning(args, client);
                break;
                
            case ProjectScannerConstants.RUN_SCAN_MODE:
                handleRunScan(args, client);
                break;
                
            case ProjectScannerConstants.PARSE_REPORT_MODE:
                handleParseReport(args, client);
                break;
                
            default:
                System.err.println("❌ Unknown mode: " + mode);
                printUsage();
        }
    }

    private static void handleListProjects(SonarQubeClient client) {
        if (!client.isAvailable()) {
            return;
        }

        ProjectManager projectManager = new ProjectManager(client);
        projectManager.listAllProjects();
    }
    
    private static void handleOrchestrateScanning(String[] args, SonarQubeClient client) {
        if (args.length < 4) {
            System.err.println("❌ Usage: java -jar fat.jar orchestrateScanning <path> <project_name> <project_key>");
            return;
        }
        
        String initialPath = args[1];
        String projectName = args[2];
        String projectKey = args[3];
        
        if (!client.isAvailable()) {
            System.err.println("❌ SonarQube server not available");
            return;
        }
        
        ProjectManager projectManager = new ProjectManager(client);
        
        // Create project if needed
        if (!projectManager.createProjectIfNotExists(projectName, projectKey)) {
            return;
        }
        
        // Generate token
        String token = projectManager.generateToken(projectName);
        if (token == null) {
            return;
        }
        
        // Save configuration
        projectManager.saveConfiguration(projectKey, token, initialPath);
        
        System.out.println("✅ Project orchestration completed!");
    }
    
    private static void handleRunScan(String[] args, SonarQubeClient client) {
        if (args.length < 2) {
            System.err.println("❌ Usage: java -jar fat.jar runScan <project_path>");
            return;
        }
        
        String projectPath = args[1];
        ScannerExecutor executor = new ScannerExecutor(client);
        executor.runScan(projectPath);
    }

    private static void handleParseReport(String[] args, SonarQubeClient client) {
        if (args.length < 2) {
            System.err.println("❌ Usage: java -jar fat.jar parseReport <project_key>");
            return;
        }
        
        String projectKey = args[1];
        String currentDir = System.getProperty("user.dir");
        
        ReportExporter exporter = new ReportExporter(client);
        exporter.exportAllReports(projectKey, currentDir);
    }
    
    private static void printUsage() {
        System.out.println("SonarQube Project Scanner");
        System.out.println("Usage:");
        System.out.println("  java -jar fat.jar listProjects");
        System.out.println("  java -jar fat.jar orchestrateScanning <path> <project_name> <project_key>");
        System.out.println("  java -jar fat.jar runScan <project_path>");
        System.out.println("  java -jar fat.jar parseReport <project_key>");
        System.out.println();
        System.out.println("Workflow:");
        System.out.println("  1. listProjects       - Discover existing projects in SonarQube");
        System.out.println("  2. orchestrateScanning - Create project and generate authentication token");
        System.out.println("  3. runScan            - Execute SonarQube scanner on project");
        System.out.println("  4. parseReport        - Export analysis results to CSV files");
    }
}
