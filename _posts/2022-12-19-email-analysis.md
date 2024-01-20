---
title: Email Analysis
author: 0wlexe
date: 2022-12-11 20:55:00 +0800
categories: [Writeups, LetsDefend]
tags: [File Analysis, Malware Analysis, Phishing]
pin: false
---


## Summary:
Your email address has been leaked and you received an email from Paypal in German. Try to analyze the suspicious email.

- **File link:** [Download](https://app.letsdefend.io/download/downloadfile/PhishingChallenge.zip/)
- **Password:** infected

This challenge was prepared by [@Fuuji](https://www.linkedin.com/in/sylvain-meurot-b34050161)

## Information we should find:
1. What is the return path of the email?
2. What is the domain name of the url in this mail?
3. Is the domain mentioned in the previous question suspicious?
4. What is the body SHA-256 of the domain?
5. Is this email a phishing email?

## Write-up

First step is to unzip the file and open the e-mail in a controlled environment so we can have a better look at it.

![Figure 01 - The suspicious e-mail received](https://miro.medium.com/v2/resize:fit:720/format:webp/1*UkxtF6x05PPXFGQwLszdcg.png)

### Translation

*Hello !*

*You are customer #12819202501 of AU Paypal Rewards and we are waiting for your confirmation since 08/09/2022.
This delivery is for you. To activate delivery, please confirm..*

*your account information*

- *Customer: Krystyalia*
- *Email: Krystyalia@gmail.com*
- *Reward: PayPal prepaid card 1000*

*[button] Continue delivery*


Inspecting the button we can find the URL where the user is supposed to be redirected to - **hxxps://storage[.]googleapis[.]com/hqyoqzatqthj/aemmfcylvxeo[.]html#QORHNZC44FT4[.]QORHNZC44FT4?dYCTywdcxr3jcxxrmcdcKBdmc5D6qfcJVcbbb4M.**

![Figure 02 - Inspecting the links in the e-mail](https://miro.medium.com/v2/resize:fit:720/format:webp/1*fXyQlPN8QoWYgGOQllv_Rw.png)

A simply analysis on VirusTotal is enough to tell it’s a possible malicious URL.

![Figure 03 - VirusTotal’s Phishing Detection](https://miro.medium.com/v2/resize:fit:720/format:webp/1*4HEVuatPn_3rhPVJEXqXeA.png)

We can also curl the domain **hxxps://storage[.]googleapis[.]com** to compute its sha256 value.

![Figure 04- Curl command: sha256sumn](https://miro.medium.com/v2/resize:fit:720/format:webp/1*L9o9ufPIgMK5uHyafKDBhg.png)

Now, by opening the header of the e-mail in a text editor, we can do a better analysis, it is possible to get: IP adress of the sender, and return-path — A return path is used to specify where bounced emails are sent and is placed in the email header. It’s an SMTP address separate from the sending address.

![Figure 05 - Designated IP and Return-Path](https://miro.medium.com/v2/resize:fit:720/format:webp/1*iRbJNASBdCweIXSw9dskNQ.png)

We can now conclude the analysis by stating it is a phishing e-mail, its main objective is to use a social engineering technique to redirect users to a malicious domain in order to collect data: possible credentials, and information from the user the e-mail is directed at.

Thank you for reading!

