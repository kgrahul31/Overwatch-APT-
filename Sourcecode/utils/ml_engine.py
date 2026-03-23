import pandas as pd
from sklearn.ensemble import IsolationForest

def detect_anomalies(event_counts):
    """
    Uses Isolation Forest to detect anomalous event occurrences.
    :param event_counts: A dictionary or pandas Series of {EventID: count}
    :return: List of EventIDs flagged as statistically anomalous.
    """
    if not event_counts or len(event_counts) < 3:
        # Not enough data to train a meaningful model
        return []

    df = pd.DataFrame(list(event_counts.items()), columns=['EventID', 'Count'])
    
    # Train Isolation Forest on the 'Count' frequency
    # We use contamination=0.1 to flag top 10% outliers
    model = IsolationForest(contamination=0.1, random_state=42)
    df['Anomaly'] = model.fit_predict(df[['Count']])
    
    # -1 means anomaly, 1 means normal
    anomalies = df[df['Anomaly'] == -1]['EventID'].tolist()
    return anomalies
