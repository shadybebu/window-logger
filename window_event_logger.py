"""
Window Logger by shadybebu
A command-line tool to parse and filter critical security events
from Windows Event Log XML files.
"""

import argparse
import sys
import xml.etree.ElementTree as ET
from datetime import datetime

# --- Configuration: Critical Event IDs and their descriptions ---
CRITICAL_EVENT_IDS = {
    '4625': 'Failed Logon: An account failed to log on (potential brute-force).',
    '4720': 'User Account Created: A new user account was created.',
    '4728': 'User Added to Global Security Group: A member was added to a security-enabled global group.',
    '4732': 'User Added to Local Security Group: A member was added to a security-enabled local group (potential privilege escalation).',
    '1102': 'Audit Log Cleared: The Security audit log was cleared (potential attempt to hide malicious activity).',
    '4776': 'Credential Validation Failure: The computer attempted to validate the credentials for an account (often related to NTLM).',
}

def print_header():
    """Prints the application header."""
    header = """
    ==================================
|  |__|  ||    ||    \ |   \   /   \ |  |__|  |      /  _]  |  |  /  _]|    \ |      |    | |     /   \  /    | /    |  /  _]|    \     
|  |  |  | |  | |  _  ||    \ |     ||  |  |  |     /  [_|  |  | /  [_ |  _  ||      |    | |    |     ||   __||   __| /  [_ |  D  )    
|  |  |  | |  | |  |  ||  D  ||  O  ||  |  |  |    |    _]  |  ||    _]|  |  ||_|  |_|    | |___ |  O  ||  |  ||  |  ||    _]|    /     
|  `  '  | |  | |  |  ||     ||     ||  `  '  |    |   [_|  :  ||   [_ |  |  |  |  |      |     ||     ||  |_ ||  |_ ||   [_ |    \     
 \      /  |  | |  |  ||     ||     | \      /     |     |\   / |     ||  |  |  |  |      |     ||     ||     ||     ||     ||  .  \    
  \_/\_/  |____||__|__||_____| \___/   \_/\_/      |_____| \_/  |_____||__|__|  |__|      |_____| \___/ |___,_||___,_||_____||__|\_|    
  by shadybebu
    ==================================
    """
    print(header)

def parse_event_log(file_path):
    """
    Parses the XML event log file and filters for critical events.

    Args:
        file_path (str): The path to the XML event log file.

    Returns:
        list: A list of dictionaries, where each dictionary represents a critical event found.
    """
    found_events = []
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
        namespace = {'ev': 'http://schemas.microsoft.com/win/2004/08/events/event'}

        print(f"[+] Processing log file: {file_path}\n")

        # Iterate through each 'Event' record in the XML file
        for event in root.findall('ev:Event', namespace):
            system_info = event.find('ev:System', namespace)
            if system_info is None:
                continue

            event_id_element = system_info.find('ev:EventID', namespace)
            if event_id_element is None:
                continue

            event_id = event_id_element.text

            # Check if the event ID is one we're monitoring
            if event_id in CRITICAL_EVENT_IDS:
                # Extract relevant details from the event
                time_created = system_info.find('ev:TimeCreated', namespace).get('SystemTime')
                computer = system_info.find('ev:Computer', namespace).text
                
                # Format the timestamp for better readability
                try:
                    dt_object = datetime.fromisoformat(time_created.replace('Z', '+00:00'))
                    formatted_time = dt_object.strftime('%Y-%m-%d %H:%M:%S UTC')
                except ValueError:
                    formatted_time = time_created # Fallback to original string

                # Extract EventData for more context if available
                event_data_details = ""
                event_data = event.find('ev:EventData', namespace)
                if event_data is not None:
                    data_points = [
                        f"{data.get('Name')}: {data.text}" 
                        for data in event_data.findall('ev:Data', namespace) 
                        if data.text
                    ]
                    event_data_details = ", ".join(data_points)

                # Store the found critical event information
                found_events.append({
                    'id': event_id,
                    'description': CRITICAL_EVENT_IDS[event_id],
                    'time': formatted_time,
                    'computer': computer,
                    'details': event_data_details if event_data_details else "No additional details found."
                })

    except FileNotFoundError:
        print(f"[!] Error: The file '{file_path}' was not found.", file=sys.stderr)
        sys.exit(1)
    except ET.ParseError:
        print(f"[!] Error: Failed to parse XML from '{file_path}'. The file may be corrupt or not a valid XML.", file=sys.stderr)
        sys.exit(1)
    
    return found_events

def display_alerts(events):
    """
    Displays the found critical events as formatted alerts on the screen.

    Args:
        events (list): A list of critical event dictionaries.
    """
    if not events:
        print("[+] Scan complete. No critical security events found.")
        return

    print(f"[!] Found {len(events)} critical security event(s)!\n")
    print("--- Alerts ---")

    for i, event in enumerate(events, 1):
        print(f"\n--- Alert #{i} ---")
        print(f"  🚨 Event ID:   {event['id']}")
        print(f"  📄 Description: {event['description']}")
        print(f"  🕒 Timestamp:  {event['time']}")
        print(f"  💻 Computer:   {event['computer']}")
        print(f"  🔍 Details:    {event['details']}")
    
    print("\n----------------\n")


def main():
    """
    Main function to orchestrate the script execution.
    """
    print_header()

    # Set up command-line argument parser
    parser = argparse.ArgumentParser(
        description='Window Logger - A tool to filter critical Windows security events from XML logs.'
    )
    parser.add_argument(
        'logfile', 
        metavar='path_to_event_log.xml', 
        type=str,
        help='The full path to the Windows Event Log file in XML format.'
    )
    
    args = parser.parse_args()

    # Parse the log file and get critical events
    critical_events = parse_event_log(args.logfile)

    # Display any alerts found
    display_alerts(critical_events)

if __name__ == '__main__':
    main()