# IT359_Project_FordOlsen
VIDEO PRESENTATION LINK: https://youtu.be/-_tynuawbEs

Project Description:
Our semester project is to take inspiration from the first project idea of automated network scanners to develop a bash script that allows an easy and user-friendly way for reconnaissance. Within this project, we plan to utilize the following tools and their capabilities: nmap, netcat, and masscan.


Project Overview:

The Automated Network Scanner is a Bash-based network reconnaissance framework designed to streamline the process of scanning hosts for open ports, services, and potential security risks. It integrates several well-known scanning tools (Nmap, Masscan, and Netcat) into a unified workflow suitable for both beginners and advanced users.

The tool supports two modes of operation: an interactive guided mode that asks the user for each configuration step, and a manual/advanced mode that accepts a full configuration string on a single line. All scan results are automatically organized into timestamped directories and exported in multiple formats, including text, CSV, and HTML. Each scan is archived into a zipped folder to maintain organization and portability.



Dependencies and Required Tools:

Required external tools  
These must be installed for the script to run:

- nmap  
- masscan  
- netcat-openbsd (or equivalent nc)  
- zip  
- sudo (needed for Masscan)


Standard utilities used  
These are included by default in most Linux environments:

- bash  
- grep  
- awk  
- sed  
- mkdir  
- rm  
- date  
- timeout  
- clear  
- printf  


Setup Instructions:

1. Download the script file and place it anywhere on your Linux system.  
2. Give the script execute permissions:

bash
chmod +x automated_network_scanner.sh


3. Confirm that all required tools are installed:

bash
nmap --version
masscan --version
nc -h


4. Run the scanner:

bash
./automated_network_scanner.sh


Usage Guide:

The Automated Network Scanner supports two modes of use.



Interactive Guided Mode

Run the script normally:


./network_scanner.sh

You will be prompted to specify:

- Target IP or hostname  
- Scanning tools to use  
- Scan flags or profiles  
- Output formats (text, CSV, HTML)  
- Verbose mode settings  

After confirming the configuration summary, the scan begins.  
Results are stored in:


scan_reports/report_<target>_<timestamp>.zip

The zip file contains:

- Text report  
- CSV report  
- HTML report  
- alerts.log  


Manual / Advanced Mode

The script can also accept a single configuration line, which allows advanced users to specify all settings at once. The format is:


<target> | tools=<list> | nmap=<flags> | masscan=<flags> | netcat=<ports> | format=<outputs> | verbose=<0|1>


Example: Quick well-known ports scan using all tools


10.0.0.58 | tools=nmap,masscan,netcat | nmap=-sV --top-ports 1000 --open | masscan=-p0-1024 --rate=5000 | netcat=21,22,23,25,53,80,110,139,143,443,445,3389 | format=text,csv,html | verbose=1

Example: Fast Nmap-only scan


192.168.1.10 | tools=nmap | nmap=-sV -T4 --top-ports 200 --open | format=html | verbose=0


Output Structure:

Each scan generates a timestamped directory containing:

- report_<target>.txt  
- report_<target>.csv  
- report_<target>.html  
- alerts.log  

This directory is then compressed into:

scan_reports/report_<target>_<timestamp>.zip


The original directory is removed automatically to conserve storage.


Summary:

The Automated Network Scanner provides a unified scanning workflow that combines powerful tools with an accessible interface. It offers both beginner-friendly guided interaction and a flexible manual mode for advanced users. Scan results are exported in multiple formats and archived cleanly, making this tool suitable for cybersecurity labs, demonstrations, coursework, and controlled reconnaissance tasks.

