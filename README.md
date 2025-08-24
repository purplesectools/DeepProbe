DeepProbe: Unmasking Hidden Threats in Memory
Automated Memory Forensics Framework with AI-Powered Intelligence

Introduction: Why DeepProbe?
In today's sophisticated threat landscape, attackers often operate in memory, leaving minimal traces on disk. Traditional forensic tools can be cumbersome, slow, and require deep manual expertise, leading to missed artifacts and prolonged incident response times. DeepProbe changes the game.

DeepProbe is not just another memory forensics tool; it's an intelligent, automated framework engineered to accelerate threat hunting and incident response. By integrating the power of Volatility 3 with an adaptive detection engine and Gemini AI-powered analytics, DeepProbe transforms raw memory dumps into actionable intelligence. It helps security analysts, forensic investigators, and threat hunters quickly uncover complex attack patterns, identify hidden processes, and reconstruct attack chains with unprecedented clarity.

What Makes DeepProbe Different?
DeepProbe stands out through its unique blend of automation, intelligence, and user-centric design:

Intelligent Correlation Engine: Unlike tools that just list individual findings, DeepProbe's core strength lies in its ability to correlate disparate forensic artifacts. It doesn't just show you a suspicious network connection; it links it to a hidden process, a code injection, and a persistence mechanism to paint a comprehensive picture of an attack. This drastically reduces false positives and highlights true threats.

AI-Powered Insights (Gemini API Integration): DeepProbe integrates with cutting-edge AI (specifically the Gemini API) to provide natural language summaries, key findings, and attack chain narratives. Imagine an AI assistant automatically explaining the "story" of an attack, detailing the attacker's tactics, techniques, and procedures (TTPs), and even suggesting potential malware families. This democratizes advanced forensics, making complex findings understandable to a wider audience.

Automated Contextualization: DeepProbe goes beyond raw data. It automatically enriches findings with contextual information, such as IP geo-location and reputation, providing immediate insights into external connections.

Streamlined User Experience: A clean, intuitive Streamlit UI abstracts away the complexities of command-line Volatility, making powerful memory forensics accessible even for those without extensive CLI experience.

Rapid Incident Response: By automating the most time-consuming aspects of memory analysis and intelligently highlighting critical findings, DeepProbe dramatically reduces the time-to-detection and time-to-containment during a security incident.

Key Capabilities & Features
Automated Memory Analysis: Leverages the robust Volatility 3 engine for deep analysis of Windows, Linux, and macOS memory dumps.

Adaptive Detection Engine: A YAML-configurable rule engine identifies known malicious behaviors and anomalies across various operating system artifacts.

Multi-Stage Attack Chain Reconstruction: Automatically correlates findings across processes, network connections, code injections, and persistence mechanisms to build a coherent attack narrative.

AI-Generated Verdicts & Summaries: Integrates with the Gemini API to provide:

High-level verdicts (e.g., "MALWARE: HIGHLY LIKELY").

Plain English summaries of the entire analysis.

Extracted key findings and detailed attack chain steps.

Potential malware family matches and confidence scores.

Identification of anomalies and corrections made during AI interpretation.

Interactive Streamlit UI:

Easy configuration of analysis jobs.

Real-time progress updates during scans.

Rich visualization of results, including:

Risk Distribution Charts: Breakdown of findings by severity (Critical, High, Medium, Low).

Technique Frequency Bar Charts: Highlighting the most prevalent MITRE ATT&CK techniques.

MITRE ATT&CK Heatmap: A visual overview of detected techniques mapped to ATT&CK tactics, with severity indicators.

Dedicated Attack Story section for narrative-driven correlated findings.

Detailed view of all detected activities with supporting evidence tables.

Comprehensive Reporting: Generates detailed reports in various formats (HTML, JSONL) for documentation and further investigation.

Raw Artifact Access: Provides direct access to raw output files from Volatility plugins (CSV, TXT, JSON) for deeper, manual investigation.

IP Enrichment: Integrates with external APIs to provide geo-location and reputation context for suspicious IP addresses found in network artifacts.

Cross-Platform Support: Analyze memory dumps from Windows, Linux, and macOS systems.

How DeepProbe Works (Technical Overview)
Memory Image Acquisition: Users provide a raw memory dump file (e.g., .raw, .vmem, hiberfil.sys).

Volatility 3 Execution: DeepProbe orchestrates the execution of various Volatility 3 plugins, extracting a wide array of forensic artifacts (e.g., process lists, network connections, loaded modules, registry keys, command line history).

Artifact Pre-processing: Raw Volatility output is parsed, normalized, and structured into a machine-readable format.

Detection Engine Analysis: A YAML-defined rule engine (detections.yaml, baseline.yaml) scans the extracted artifacts for suspicious indicators, known malware patterns, and deviations from a baseline.

Correlation Engine: This is where DeepProbe's intelligence shines. It takes individual findings and cross-references them to identify causal links and temporal relationships. For example, a hidden process, a code injection in that process, and an outbound network connection from it would be correlated into a single "Attack Chain" finding.

IP Enrichment (Optional): If an API key is provided, detected external IP addresses are enriched with geo-location and reputation data.

AI Verdict Generation (Optional): If an OpenAI API key is provided, the Gemini API is called to process the structured findings and generate a human-readable summary, key findings, attack chain narrative, and potential malware match.

Report Generation: All findings, correlations, and AI insights are compiled into an interactive Streamlit UI and comprehensive output files.

Getting Started
To run DeepProbe, you'll need Docker installed on your system.

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


This command downloads the necessary Python and Debian base images, installs Volatility 3, sets up Python dependencies, and packages your DeepProbe application. This might take a few minutes for the first build.

Running the Application (Securely Local)
To run DeepProbe and access it securely from your local machine (browser), follow these steps:

Create an Isolated Docker Network: This provides an additional layer of network isolation for your container.

docker network create isolated-net

Run the Container on the Isolated Network: This command ensures the application is only accessible via localhost and not exposed on any public or network IP addresses.

docker run --rm --network=isolated-net -p 127.0.0.1:8501:8501 \
  -v $(pwd)/memory:/app/memory \
  -v $(pwd)/out:/app/out \
  deeprobe-app

-p 127.0.0.1:8501:8501: Maps port 8501 inside the container to port 8501 on your host machine, specifically binding it to the localhost interface. This prevents external access.

-v $(pwd)/memory:/app/memory: Mounts your local memory directory into the container. Place your memory dump files here.

-v $(pwd)/out:/app/out: Mounts your local out directory into the container. Analysis results and reports will be saved here.

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

IP Enrichment API Key: Provide an API key for services that offer IP geo-location and reputation.

OpenAI API Key: Provide your OpenAI API key to enable AI-generated summaries and verdicts.

Launch Analysis: Click "Launch Analysis" to start the automated forensic scan.

Review Results: Once the scan is complete, explore the "Report Summary", "Findings", and "Artifacts" tabs for detailed insights, visualizations, and AI narratives.

Output & Reporting
All generated analysis reports, detailed findings (JSONL), AI verdicts (JSON), and raw artifact files from Volatility plugins will be saved in the out/<PROJECT_NAME>/ directory on your host machine. This allows for offline review and integration with other tools.

Contributing
We welcome contributions from the community! If you'd like to improve DeepProbe, please refer to our CONTRIBUTING.md (coming soon!) for guidelines on how to report bugs, suggest features, and submit pull requests.

License
This project is licensed under the MIT License - see the LICENSE file for details.
