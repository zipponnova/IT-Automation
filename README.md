# What is Bakshi?

Bakshi is tool that compares 6sense MDM hosts with Crowdstrike to understand IT/Security Posture.

# How does this work?
- Upload MDM user data from JAMF, Jumpcloud and Intune to compare the results.
- The powerful APIs of Crowdstrike and MDM pulls the data to create multiple comparison reports in the app.
- Add more APIs from other MDMs.
- Store all the secrets in the bashrc to run the app.

# How to setup environment?

- Git clone & run

```
git clone https://github.com/6si/security/tree/main/it-automation/Bakshi
source ~/.bashrc
python3 Bakshi_app.py
```

- The application runs on port `8040`

- Only run this app in dev environment.
