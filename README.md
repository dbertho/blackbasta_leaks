# BlackBasta Ransomware leaked chats

## Overview

This repository contains the original leaked file and an analysis of the chats. The data has been extracted and processed to provide insights into the operations, tactics, and communications of the BlackBasta ransomware group. The goal of this repository is to offer a structured examination of the leaked information.

## Contents

- **Data Files**:
  - `blackbasta_chat_logs.zip`: Raw chat logs from the BlackBasta ransomware group.
  - `bestflowers_clean.zip`: Cleaned-up (valid) non-translated JSON file.
  - `cve_list.csv`: List of CVEs mentioned in the leak, and some context, including date of publication and addition to the CISA KEV list.
  - `rmm.csv`: List of Remote Monitoring and Management (RMM) tools mentioned in the leak.
  - `user_activity.csv`: User activity logs.

- **Scripts**:
  - `extract_cve.py`: Script to extract CVE information from the chat logs.
  - `translator.py`: Script to translate chat logs into English, using the Google Translate API.
