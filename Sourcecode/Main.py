import win32evtlog  # For reading Windows Event Logs
import pandas as pd
import os

# Define Event Log Categories
event_logs = ['Security', 'System', 'Application']

# Read event logs
def read_windows_event_logs(log_type, max_events=100):
    """Read specified type of Windows event logs."""
    logs = []
    try:
        handler = win32evtlog.OpenEventLog(None, log_type)
        total_logs = win32evtlog.GetNumberOfEventLogRecords(handler)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        events = win32evtlog.ReadEventLog(handler, flags, 0)

        for event in events:
            event_data = {
                'SourceName': event.SourceName,
                'EventID': event.EventID,
                'Category': event.EventCategory,
                'TimeGenerated': event.TimeGenerated,
                'EventType': event.EventType,
                'EventCategory': event.EventCategory,
                'InsertionStrings': event.StringInserts
            }
            logs.append(event_data)
            if len(logs) >= max_events:
                break
    except Exception as e:
        print(f"Failed to read {log_type} logs: {e}")
    return logs

# Analyze event logs
def analyze_logs(logs):
    """Basic analysis to detect APT-like suspicious activities."""
    suspicious_events = []
    
    # Example rule 1: Look for process creations or privilege escalations (EventID 4688, 4673)
    suspicious_event_ids = [4688, 4673, 4624]  # Add more Event IDs for hunting
    for log in logs:
        if log['EventID'] in suspicious_event_ids:
            suspicious_events.append(log)

    return suspicious_events

# Load and process logs
def hunt_apt():
    """Main function for reading and analyzing logs."""
    all_suspicious_activities = []
    
    for log_type in event_logs:
        print(f"Reading {log_type} logs...")
        logs = read_windows_event_logs(log_type)
        print(f"Analyzing {log_type} logs...")
        suspicious_activities = analyze_logs(logs)
        all_suspicious_activities.extend(suspicious_activities)
    
    return pd.DataFrame(all_suspicious_activities)

# Visualize suspicious events
def visualize_results(df):
    """Visualize the frequency of suspicious events detected."""
    import matplotlib.pyplot as plt
    import seaborn as sns

    plt.figure(figsize=(10, 6))
    sns.countplot(x='EventID', data=df)
    plt.title('Frequency of Suspicious Event IDs Detected')
    plt.xlabel('Event ID')
    plt.ylabel('Count')
    plt.show()

# Main script execution
if __name__ == "__main__":
    suspicious_df = hunt_apt()

    if not suspicious_df.empty:
        print("Suspicious activities detected:")
        print(suspicious_df)
        
        # Visualize the detected suspicious activities
        visualize_results(suspicious_df)
    else:
        print("No suspicious activities detected.")
