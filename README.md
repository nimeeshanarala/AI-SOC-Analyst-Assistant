# AI SOC Analyst Assistant

An AI-powered cybersecurity dashboard that analyzes security logs, identifies suspicious activity, and provides security analysis and recommended actions using the OpenAI API.

## Project Overview

The AI SOC Analyst Assistant is a beginner-friendly cybersecurity project designed to simulate part of a Security Operations Center (SOC) workflow.

The application allows a security analyst to upload CSV security logs, review security events, filter and search the logs, and use AI to analyze suspicious activity.

The application combines traditional Python-based detection rules with AI-assisted security analysis.

## Features

- Upload CSV security logs
- Analyze security events using Python and Pandas
- Automatically assign security severity levels:
  - Low
  - Medium
  - High
  - Critical
- Detect multiple failed login attempts
- Provide explanations for detected security events
- Filter logs by severity
- Search security logs
- Display security event statistics
- Visualize events by severity
- Select individual security events for AI analysis
- Provide surrounding log context to the AI
- Generate AI-powered incident summaries
- Provide recommended investigation and response actions

## Technologies Used

- Python
- Pandas
- Streamlit
- Matplotlib
- OpenAI API
- python-dotenv
- Git/GitHub

## How It Works

```text
Security Log CSV
       ↓
Python/Pandas
       ↓
Security Event Detection
       ↓
Severity Classification
       ↓
Streamlit Dashboard
       ↓
Analyst Selects Event
       ↓
Surrounding Log Context
       ↓
OpenAI API
       ↓
AI Security Analysis
       ↓
Incident Summary + Recommended Actions