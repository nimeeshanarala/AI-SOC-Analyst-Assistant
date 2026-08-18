import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import os

from dotenv import load_dotenv
from openai import OpenAI


load_dotenv()

client = OpenAI(
    api_key=os.getenv("OPENAI_API_KEY")
)

def ask_ai(question):

    response = client.responses.create(
        model="gpt-5",
        input=question
    )

    return response.output_text

st.title("AI SOC Analyst Assistant")


def get_severity(event):

    if event == "Login Success":
        return "Low"

    elif event == "Login Failed":
        return "Medium"

    elif event == "Multiple Failed Logins":
        return "High"

    elif event == "Firewall Disabled":
        return "Critical"

    elif event == "PowerShell Executed":
        return "High"

    elif event == "New User Created":
        return "Medium"

    elif event == "File Deleted":
        return "Low"

    else:
        return "Unknown"



def get_reason(event):

    if event == "Login Success":
        return "User successfully logged in. This is normal activity."

    elif event == "Login Failed":
        return "A failed login could indicate an incorrect password or an attacker trying to gain access."

    elif event == "Multiple Failed Logins":
        return "Multiple failed logins may indicate a brute-force attack."

    elif event == "PowerShell Executed":
        return "PowerShell is commonly used by administrators but can also be abused by attackers."

    elif event == "New User Created":
        return "A new account was created. Verify that this action was authorized."

    elif event == "File Deleted":
        return "Files were deleted. This may be normal or require investigation."

    elif event == "Firewall Disabled":
        return "The firewall was disabled, reducing system protection."

    else:
        return "No explanation available."



upload_file = st.file_uploader(
    "Upload a Security Log",
    type=["csv"]
)

if upload_file:
    df = pd.read_csv(upload_file)

    df["Severity"] = df["Event"].apply(get_severity)
    df["Reason"] = df["Event"].apply(get_reason)

    failed_logins = (
    df[df["Event"] == "Login Failed"]
    .groupby("User")
    .size()
    )

    for user, count in failed_logins.items():
        if count >= 3:

            df.loc[
                (df["User"] == user) &
                (df["Event"] == "Login Failed"),
                "Severity"
            ] = "High"

            df.loc[
                (df["User"] == user) &
                (df["Event"] == "Login Failed"),
                "Reason"
            ] = "Possible brute-force attack: 3 or more failed login attempts detected."

    critical_count = (df["Severity"] == "Critical").sum()
    high_count = (df["Severity"] == "High").sum()
    medium_count = (df["Severity"] == "Medium").sum()
    low_count = (df["Severity"] == "Low").sum()

    st.success("Log uploaded successfully!")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Critical", critical_count)
    col2.metric("High", high_count)
    col3.metric("Medium", medium_count)
    col4.metric("Low", low_count)

    severity_counts = df["Severity"].value_counts()

    fig, ax = plt.subplots()

    ax.bar(severity_counts.index, severity_counts.values)

    ax.set_title("Security Events by Severity")
    ax.set_xlabel("Severity")
    ax.set_ylabel("Number of Events")

    st.pyplot(fig)
    

    severity_filter = st.selectbox(
    "Filter by Severity",
    ["All", "Critical", "High", "Medium", "Low"]
    )

    search = st.text_input("Search Logs")

    filtered_df = df

    if severity_filter != "All":
        filtered_df = filtered_df[
        filtered_df["Severity"] == severity_filter
        ]

    if search:
        filtered_df = filtered_df[
        filtered_df.astype(str).apply(
            lambda row: row.str.contains(search, case=False).any(),
            axis=1
            )
        ]
    st.dataframe(filtered_df)


    st.subheader("AI Security Analyst")

    event_index = st.selectbox(
    "Select an event to analyze",
    filtered_df.index,
    format_func=lambda i: (
        f"{filtered_df.loc[i, 'Event']} — "
        f"{filtered_df.loc[i, 'Severity']}"
        )
    )

    if st.button("Analyze with AI"):

        selected_event = filtered_df.loc[event_index]

        start_index = max(0, event_index - 2)
        end_index = min(len(df), event_index + 3)

        context_df = df.iloc[start_index:end_index]

        context_text = context_df.to_string(index=False)

        event = selected_event["Event"]
        severity = selected_event["Severity"]
        reason = selected_event["Reason"]

        prompt = f"""
        You are a cybersecurity SOC analyst.

        Analyze this security event and the surrounding log activity.

        Event: {event}
        Severity: {severity}
        Reason: {reason}

        Surrounding Logs:
        {context_text}

        Create a concise incident summary.

        Include:

        Incident Summary:
        Briefly explain what happened.

        Why It Matters:
        Explain why the activity may be concerning.

        Recommended Actions:
        Give 2-3 practical investigation or response steps.

        Do not assume the activity is malicious without evidence.
        Clearly separate observed facts from possible explanations.
        Keep the response concise and easy for a SOC analyst to understand.
        """

        answer = ask_ai(prompt)

        st.subheader("AI Incident Analysis")
        st.write(answer)


