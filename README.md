# SonarQube Project Scanner

Java application that automates SonarQube project management and security scanning through the SonarQube REST API.

**Requires**: This application runs on top of the [SonarQube Scanner Container](https://github.com/jpruiz114/sonarqube-scanner-container)

## Prerequisites

- Java 11+
- Gradle 7.6+
- Running SonarQube server (via Docker container from [sonarqube-scanner-container](https://github.com/jpruiz114/sonarqube-scanner-container))

## Build

```bash
./gradlew buildFatJar
```

## Usage Examples

### ORCHESTRATE SCANNING Mode

Sets up project and generates authentication token:

```bash
java -jar build/libs/fat.jar orchestrateScanning /path/to/project "Project Name" "project-key"
```

**What it does:**
- Creates SonarQube project
- Generates access token
- Saves configuration to `sq_variables.config`

### RUN SCAN Mode

Executes SonarQube scanner on your code:

```bash
# First: Mount your project to Docker container
docker run -d --name sonarqube-scanner \
  -p 9001:9000 \
  -v /path/to/your/project:/workspace \
  jpruiz114/sonarqube-with-sonarscanner

# Then: Run the scan
java -jar build/libs/fat.jar runScan /path/to/your/project
```

**What it does:**
- Reads configuration from `sq_variables.config`
- Executes sonar-scanner inside Docker container
- Analyzes source code and uploads results

### LIST PROJECTS Mode

Lists all projects in SonarQube:

```bash
java -jar build/libs/fat.jar listProjects
```

**What it does:**
- Connects to SonarQube server
- Displays table of all projects with names and keys
- Helps you find existing project keys for other operations

### PARSE REPORT Mode

Extracts scan results to CSV files:

```bash
java -jar build/libs/fat.jar parseReport "project-key"
```

**What it does:**
- Downloads issues by severity (BLOCKER, CRITICAL, MAJOR, MINOR, INFO)
- Downloads security hotspots
- Exports all data to CSV files in `/reports/<project-key>/` directory

## Complete Workflow

```bash
# 0. List existing projects (optional)
java -jar build/libs/fat.jar listProjects

# 1. Setup project and token
java -jar build/libs/fat.jar orchestrateScanning /path/to/project "My Project" "my-key"

# 2. Run analysis
java -jar build/libs/fat.jar runScan /path/to/project

# 3. Export results to CSV
java -jar build/libs/fat.jar parseReport "my-key"
```

## Generated Files

- `sq_variables.config` - Project configuration and access token
- `reports/<project-key>/BLOCKER.csv` - Critical blocking issues
- `reports/<project-key>/CRITICAL.csv` - Critical severity issues
- `reports/<project-key>/MAJOR.csv` - Major severity issues
- `reports/<project-key>/MINOR.csv` - Minor severity issues
- `reports/<project-key>/INFO.csv` - Informational issues
- `reports/<project-key>/hotspots.csv` - Security hotspots