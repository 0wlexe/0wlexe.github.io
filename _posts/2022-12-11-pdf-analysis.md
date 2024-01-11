---
title: PDF Analysis
author: 0wlexe
date: 2022-12-11 20:55:00 +0800
categories: [Walkthroughs, LetsDefend]
tags: [Wireshark, File Analysis, malware analysis]
pin: false
img_path: 'https://miro.medium.com/v2/resize:fit:720/format:webp/1*FrflEPS13OZ9W0SUdk0owQ.png'
---

## Summary:
Analysis of a PDF file in order to detect if there’s any signs of malicious behavior and possible indicators of compromise.

Under the scenery that an employee has received the following email:

```sass
From: systemsupdate@letsdefend.io
To: paul@letsdefend.io
Subject: Critical — Annual Systems UPDATE NOW
Body: Please do the dutiful before the deadline today.
Attachment: Update.pdf
Password: letsdefend
```

![Figure 01 - Simulation of the e-mail](https://miro.medium.com/v2/resize:fit:720/format:webp/1*e2ypH0L_zoVi--rIYGxseQ.png)

The employee has reported this incident to you as the analyst which has also forwarded the attachment to your SIEM. They have mentioned that they did not download or open the attachment as they found it very suspicious. They wish for you to analyze it further to verify its legitimacy.

NOTE: Do not open in your local environment. It is a malicious file.

This challenge prepared by @DXploiter.

### Information we should find
1. What local directory name would have been targeted by the malware?
2. What would have been the name of the file created by the payload?
3. What file type would this have been if it were created?
4. Which external web domain would the malware have attempted to interact with?
5. Which HTTP method would it have used to interact with this service?
6. What is the name of the obfuscation used for the Javascript payload?
7. Which tool would have been used for creating the persistence mechanism?
8. How often would the persistence be executed once Windows starts? (format: X.X hours)?
9. Which LOLBin would have been used in the persistence method?
10. What is the filename that would have been downloaded and executed using the LOLbin?
11. Where would this have been downloaded from? (format: IP address)
12. Which country is this IP Address located in?


    
