DeepProbe: Unmasking Hidden Threats in Memory
Automated Memory Forensics Framework with AI-Powered Intelligence
Introduction: Why DeepProbe?
In today's sophisticated threat landscape, attackers often operate in memory, leaving minimal traces on disk. Traditional forensic tools can be cumbersome, slow, and require deep manual expertise, leading to missed artifacts and prolonged incident response times. DeepProbe changes the game.

DeepProbe is not just another memory forensics tool; it's an intelligent, automated framework engineered to accelerate threat hunting and incident response. By integrating the power of the Volatility 3 Framework with an adaptive detection engine and AI-powered analytics, DeepProbe transforms raw memory dumps into actionable intelligence. It helps security analysts, forensic investigators, and threat hunters quickly uncover complex attack patterns, identify hidden processes, and reconstruct attack chains with unprecedented clarity.

What Makes DeepProbe Different?
DeepProbe stands out through its unique blend of automation, intelligence, and user-centric design:

Intelligent Correlation Engine: Instead of just listing individual findings, DeepProbe's core strength is its ability to correlate disparate forensic artifacts. It doesn't just show you a suspicious network connection; it links it to a hidden process, a code injection, and a persistence mechanism to paint a comprehensive picture of an attack. This drastically reduces false positives and highlights true threats.

AI-Powered Insights: DeepProbe integrates with the Gemini API to provide natural language summaries, key findings, and attack chain narratives. This feature democratizes advanced forensics, making complex findings understandable to a wider audience.

Automated Contextualization: DeepProbe goes beyond raw data by automatically enriching findings with contextual information, such as IP geo-location and reputation, for immediate insights into external connections.

Streamlined User Experience: A clean, intuitive Streamlit UI abstracts away the complexities of command-line Volatility, making powerful memory forensics accessible even for those without extensive CLI experience.

Rapid Incident Response: By automating the most time-consuming aspects of memory analysis and intelligently highlighting critical findings, DeepProbe dramatically reduces the time-to-detection and time-to-containment during a security incident.

Key Capabilities & Features
Automated Memory Analysis: Leverages the robust Volatility 3 engine for deep analysis of Windows, Linux, and macOS memory dumps.

Adaptive Detection Engine: A YAML-configurable rule engine identifies known malicious behaviors and anomalies across various operating system artifacts.

Multi-Stage Attack Chain Reconstruction: Automatically correlates findings across processes, network connections, code injections, and persistence mechanisms to build a coherent attack narrative.

AI-Generated Verdicts & Summaries: Provides high-level verdicts, plain-English summaries, and detailed attack chain steps.

Interactive Streamlit UI: Offers easy configuration of analysis jobs and real-time progress updates.

Comprehensive Reporting: Generates detailed reports in various formats (HTML, JSONL) for documentation and further investigation.

IP Enrichment: Integrates with AbuseIPDB to provide geo-location and reputation context for suspicious IP addresses.

Cross-Platform Support: Analyze memory dumps from Windows, Linux, and macOS systems.

Getting Started
DeepProbe runs securely within a Docker container.

Prerequisites
Docker Desktop: Install Docker Desktop for macOS, Windows, or your preferred Docker engine for Linux. Ensure it's running before proceeding.

Setup Files
Ensure the following files are in your project's root directory:

Dockerfile

app.py

runner.py

requirements.txt

detections.yaml

baseline.yaml

README.md

LICENSE

.gitignore

.dockerignore

An empty memory/ subdirectory (create this if it doesn't exist)

An empty out/ subdirectory (create this if it doesn't exist)

Building the Docker Image
Navigate to your project directory in the terminal and build the Docker image:

docker build -t deeprobe-app .

This command downloads the necessary base images, installs Volatility 3, sets up Python dependencies, and packages your DeepProbe application. This might take a few minutes for the first build.

Running the Application (Securely Local)
To run DeepProbe and access it securely from your local machine (browser), follow these steps:

Create an Isolated Docker Network: This provides an additional layer of network isolation for your container.

docker network create isolated-net

Run the Container on the Isolated Network: This command ensures the application is only accessible via localhost and is not exposed on any public or network IP addresses.

docker run --rm --network=isolated-net -p 127.0.0.1:8501:8501 \
    -v "$(pwd)"/memory:/app/memory \
    -v "$(pwd)"/out:/app/out \
    deeprobe-app

-p 127.0.0.1:8501:8501: Maps port 8501 inside the container to port 8501 on your host machine, specifically binding it to the localhost interface. This prevents external access.

-v "$(pwd)"/memory:/app/memory: Mounts your local memory directory into the container. Place your memory dump files here.

-v "$(pwd)"/out:/app/out: Mounts your local out directory into the container. Analysis results and reports will be saved here.

--rm: Automatically removes the container once it exits.

--network=isolated-net: Connects the container to the isolated network you created, enhancing security.

Accessing the UI
Once the container is running, open your web browser and navigate to:

http://localhost:8501

You should see the DeepProbe UI ready for use.

Using DeepProbe
Place Memory Image: Copy your memory dump file (e.g., my_workstation.raw) into the memory/ folder in your project directory (on your host machine).

Configure Analysis: In the UI, enter a Project Name and the Memory File Name (e.g., my_workstation.raw).

API Keys (Optional):

AbuseIPDB API Key: Provide an API key from AbuseIPDB for IP geo-location and reputation analysis.

Gemini API Key: Provide your Gemini API key to enable AI-generated summaries and verdicts.

Launch Analysis: Click Launch Analysis to start the automated forensic scan.

Review Results: Once the scan is complete, explore the "Report Summary", "Findings", and "Artifacts" tabs for detailed insights and AI narratives.

Output & Reporting
All generated analysis reports, detailed findings (JSONL), and raw artifact files from Volatility plugins will be saved in the out/<PROJECT_NAME>/ directory on your host machine. This allows for offline review and integration with other tools.

License
DeepProbe is a wrapper built on the Volatility 3 Framework, and as such, it is licensed under the Volatility Software License (VSL), Version 1.0.

The VSL is a copyleft license that requires any additions or wrappers built on the Volatility Framework to also be made publicly available under the same license. This ensures the project remains open and accessible to all.

A full copy of the license is available in the LICENSE file in this repository.

Contributing
We welcome contributions from the community! If you'd like to improve DeepProbe, please refer to our CONTRIBUTING.md (coming soon!) for guidelines on how to report bugs, suggest features, and submit pull requests.
