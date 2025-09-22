# SonarQube Project Scanner

Java application that automates SonarQube project management and security scanning through the SonarQube REST API.

## Prerequisites

- Java 11+
- Gradle 7.6+
- Running SonarQube server (via Docker container)

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

### PARSE REPORT Mode

Extracts scan results to CSV files:

```bash
java -jar build/libs/fat.jar parseReport /path/to/project "project-key"
```

**What it does:**
- Downloads issues by severity (BLOCKER, CRITICAL, MAJOR, MINOR, INFO)
- Downloads security hotspots
- Exports all data to CSV files in `/reports/` directory

## Complete Workflow

```bash
# 1. Setup
java -jar build/libs/fat.jar orchestrateScanning /path/to/project "My Project" "my-key"

# 2. Scan
java -jar build/libs/fat.jar runScan /path/to/project

# 3. Export
java -jar build/libs/fat.jar parseReport /path/to/project "my-key"
```

## Generated Files

- `sq_variables.config` - Project configuration and access token
- `reports/BLOCKER.csv` - Critical blocking issues
- `reports/CRITICAL.csv` - Critical severity issues
- `reports/MAJOR.csv` - Major severity issues
- `reports/MINOR.csv` - Minor severity issues
- `reports/INFO.csv` - Informational issues
- `reports/hotspots.csv` - Security hotspots