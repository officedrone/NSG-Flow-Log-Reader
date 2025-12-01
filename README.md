# NSG Flow Log JSON Viewer

A GUI application for parsing and visualizing Azure Network Security Group (NSG) Flow Logs from JSON files.

## Requirements

- Python 3.x
- Tkinter (usually included with Python)
- Raw vNet flow logs in JSON format in the same folder (or subfolders) as the script

## Usage

1. Run the application in the directory containing your NSG flow log JSON files. You can run it by opening a command prompt and executing 'python NSGFlowLogReader.py'
2. Double-click or select files and click "Open Selected", or highlight a file and click 'Open Selected File' button
3. Browse and search through network flow records
4. Use copy buttons to export data for analysis


<img width="1549" height="1052" alt="image" src="https://github.com/user-attachments/assets/e84bc454-dd6c-4329-9618-d42ef26faaf0" />




## Features
- **File Management**: Automatically loads all JSON files from current directory and subdirectories
- **Data Parsing**: Converts vNet flow log records into readable format with:
  - Protocol mapping (6 → TCP, 17 → UDP)
  - Flow direction mapping (I → Inbound, O → Outbound)
  - Encryption status mapping (NX → Not Encrypted, E → Encrypted)
  - Flow state mapping (B → Begin, C → Continuing, E → End, D → Deny)
  - Timestamp conversion from Unix epoch to readable format
- **Search Functionality**: 
  - Partial match searching across all fields
  - Exact match support using quotes (e.g., "Exact Match")
  - Real-time filtering as you type
- **Highlighting**: 
  - Automatically highlights denied flows in light red background
- **Data Export**: Copy data to clipboard in CSV or Excel (TSV) format
- **Responsive UI**: Auto-sizing window and column widths based on content

## ToDo
- NSG flow logs support (currently only vNet flow logs are supported)

## App Windows description

### Main Window
- Displays list of JSON files in current directory and subdirectories
- File browser with scrollbar
- Control buttons: "Open Selected" (open hihghlited file from list), "Refresh File List" (refresh the list), "Open Other" (opens files from the file system)
- Status bar showing application status

### Data Display Window
- **Title**: Shows filename being displayed
- **Search Bar**: Real-time filtering with partial/quoted exact matching
- **Table View**: Treeview displaying parsed flow records with all fields
- **Highlighting**: Denied flows (flowState = D) shown in light red background
- **Buttons**: Copy to clipboard (CSV or Excel format), Close


## Tuple Fields Description

Each flow tuple contains 13 fields in the following order:
1. **Timestamp** - Unix epoch timestamp (converted to readable date/time)
2. **sourceIP** - Source IP address
3. **destIP** - Destination IP address
4. **sourcePort** - Source port number
5. **destPort** - Destination port number
6. **proto** - Protocol number (6 = TCP, 17 = UDP)
7. **trafficFlow** - Flow direction (I = Inbound, O = Outbound)
8. **flowState** - Flow state (B = Begin, C = Continuing, E = End, D = Deny)
9. **encryption** - Encryption status (NX = Not Encrypted, E = Encrypted)
10. **packetsSrcToDest** - Number of packets from source to destination
11. **bytesSrcToDest** - Number of bytes from source to destination
12. **packetsDstToSrc** - Number of packets from destination to source
13. **bytesDestToSrc** - Number of bytes from destination to source



The application is designed for security analysts and network administrators to examine NSG flow logs for troubleshooting and monitoring network traffic patterns.
