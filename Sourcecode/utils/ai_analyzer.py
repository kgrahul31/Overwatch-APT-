import json
from google import genai

def analyze_threats_with_ai(api_key, threats_list, raw_xml_sample):
    """
    Calls the Google Gemini API to analyze the detected threats and provide a professional SOC summary.
    """
    if not api_key:
        return "⚠️ **AI Settings Incomplete**: Please add your Google Gemini API Key in the Settings tab."
    
    if not threats_list:
        return "No threats detected to analyze."

    prompt = f"""
    You are an expert Security Operations Center (SOC) analyst.
    I have an Overwatch-APT threat detection system that analyzed a Windows Event Log (.evtx) file.
    It found the following suspicious activities: {', '.join(threats_list)}.
    
    Here is a sample of the raw XML event data related to these alerts:
    {raw_xml_sample[:1500]} 

    Please write a professional Incident Response summary including:
    1. A high-level executive summary of what likely happened.
    2. The potential impact of this attack chain.
    3. Step-by-step remediation actions a system administrator should take immediately to secure the system.
    
    Format your response in Markdown with clear headers and bullet points.
    """

    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model='gemini-2.5-pro',
            contents=prompt,
        )
        return response.text
    except Exception as e:
        return f"❌ **AI Analysis Failed**: {str(e)}"
