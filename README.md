# What is Bakshi?

Bakshi is tool that compares 6sense MDM hosts with Crowdstrike to understand IT/Security Posture.

# How does this work?
- Currently one need to upload CSV files from different sources to identify discrepancies.
- Crowdstrike API has been added so need to get csv of crowdstrike host.
- Get CSV from JAMF, JumpCloud and Intune.

# How to setup environment?

- Git clone & run

```
git clone https://github.com/6si/security/tree/main/it-automation/Bakshi
python3 Bakshi_app.py
```

- The application runs on port `8040`

- Only run this app in dev environment.
