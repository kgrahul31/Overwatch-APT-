import streamlit as st
import base64
import tempfile
import re
import matplotlib.pyplot as plt
import pandas as pd
import Evtx.Evtx as evtx
import os

def get_base64(bin_file):
    with open(bin_file, 'rb') as f:
        data = f.read()
    return base64.b64encode(data).decode()

def set_background(png_file):
    bin_str = get_base64(png_file)
    page_bg_img = '''
    <style>
    .stApp {
    background-image: url("data:background/background.avif;base64,%s");
    background-position: center;
    background-size: cover;
    }
    </style>
    ''' % bin_str
    st.markdown('<style>h1 { color: White ; }</style>', unsafe_allow_html=True)
    st.markdown('<style>p { color: Black; }</style>', unsafe_allow_html=True)
    st.markdown(page_bg_img, unsafe_allow_html=True)

set_background('background/2.jpg')

# Function to detect potential threats based on log content
def detect_threats(log_data):
    threats = []

    # Define some suspicious activities or patterns (IOCs)
    if re.search(r'failed login|logon failure', log_data, re.IGNORECASE):
        threats.append("Failed login attempts")
    if re.search(r'account locked out', log_data, re.IGNORECASE):
        threats.append("Account lockout events")
    if re.search(r'new process|process created', log_data, re.IGNORECASE):
        threats.append("Suspicious process execution")
    if re.search(r'privilege escalation|elevated privileges', log_data, re.IGNORECASE):
        threats.append("Privilege escalation")
    if re.search(r'malware|ransomware|malicious', log_data, re.IGNORECASE):
        threats.append("Potential malware or ransomware")
    if re.search(r'unauthorized access|critical file accessed', log_data, re.IGNORECASE):
        threats.append("Unauthorized access to critical files")
    if re.search(r'new user account|account created', log_data, re.IGNORECASE):
        threats.append("New user account creation")
    if re.search(r'port scan|unusual network traffic', log_data, re.IGNORECASE):
        threats.append("Suspicious network activity (possible port scanning)")
    if re.search(r'registry change|registry key modified', log_data, re.IGNORECASE):
        threats.append("Suspicious registry changes")
    if re.search(r'firewall disabled|anti-virus disabled', log_data, re.IGNORECASE):
        threats.append("Firewall or anti-virus disabled")
    if re.search(r'scheduled task created', log_data, re.IGNORECASE):
        threats.append("Suspicious scheduled task")

    return threats

# Title of the app
st.title("Overwatch-apt Threat Detection")

# File uploader in Streamlit
uploaded_file = st.file_uploader("Upload an .evtx file", type=["evtx"])

# If a file is uploaded
if uploaded_file is not None:
    try:
        # Create a temporary file to store the uploaded EVTX file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(uploaded_file.read())
            temp_file_path = temp_file.name

        # Try reading the EVTX file from the temporary file
        threat_found = False
        threat_messages = []
        all_threats = []
        with evtx.Evtx(temp_file_path) as log:
            for record in log.records():
                xml_data = record.xml()
                st.text_area("EVTX Record", xml_data)
                
                # Detect threats in the log data
                threats = detect_threats(xml_data.lower())  # Convert to lowercase for case-insensitive search
                if threats:
                    threat_found = True
                    threat_messages.extend(threats)
                    all_threats.extend(threats)

        # Clean up the temporary file after reading
        os.remove(temp_file_path)

        # Show threat detection results
        if threat_found:
            st.warning("Suspicious Activities Detected!")
            for message in threat_messages:
                st.error(message)
            
            # Count occurrences of each threat
            threat_count = pd.Series(all_threats).value_counts()

            # Plotting the threats using Matplotlib
            fig, ax = plt.subplots()
            threat_count.plot(kind='bar', ax=ax)
            ax.set_title("Threat Detection Count")
            ax.set_xlabel("Threat Types")
            ax.set_ylabel("Count")
            st.pyplot(fig)

        else:
            st.success("No suspicious activities detected.")

    except Exception as e:
        st.error(f"Error reading {uploaded_file.name}: {e}")
else:
    st.info("Please upload an .evtx file to view its content.")
