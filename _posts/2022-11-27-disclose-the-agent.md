---
title: Disclose The Agent
author: 0wlexe
date: 2022-11-27 20:55:00 +0800
categories: [Walkthroughs, LetsDefend]
tags: [Wireshark, File Analysis, SMTP]
pin: false
img_path: /assets/img/posts/agent.png
---

## Summary:
We reached the data of an agent leaking information. You have to disclose the agent.

- **Log file:** [Download](https://app.letsdefend.io/download/downloadfile/smtpchallenge.zip) 
- **Pass:** 321

***Note: pcap file found public resources.***

### Information we should find

1. Secret boyfriend’s email address;
2. Ann’s email password;
3. The secret file Ann sent to her secret lover;
4. The location where Ann will meet her secret lover;
5. MD5 hash of the file Ann provided to her lover.


#### Observations:
If you plan on doing the LetsDefend challenge, I strongly recommend trying to do it by yourself before reading!

## Walkthrough
First step was to open the PCAP file in a network protocol analyzer, for this task I’ll be using Wireshark so we can better analyze the traffic data.

Having in mind that our first goal is to find a secret e-mail address, we can start by searching for the SMTP (Simple Mail Transfer Protocol) on Wireshark.

![Figure 01: Wireshark SMTP Filter](https://miro.medium.com/v2/resize:fit:720/format:webp/1*jGOjJUyoR3b9lWpTZmY3Lg.png)

Looking at the traffic data, we can already detect some valuable information:

- There was a parameter request for user authentication `(Request Parameter: LOGIN)`;
- `EHLO annlaptop` - Possible name of the machine of which was requested the user authentication;
- User: `c25lYWt5ZzMza0Bhb2wuY29t` (Base64 Cryptographed username);
- Pass: `NTU4cjAwbHo=` (Base64 Cyptographed password).

Assuming this is Ann’s computer (EHLO annlaptop), we could find her credentials by decoding her username and password values.

There are many online decoder tools we could use to decode a specific line of cryptography, for this instance we’ll be using Code Beautify to get both username and password.

![Figure 03: Ann’s username (e-mail)](https://miro.medium.com/v2/resize:fit:720/format:webp/1*YGg597w-5cYEuMm6ME6SRQ.png)

![Figure 04: Ann’s Password](https://miro.medium.com/v2/resize:fit:720/format:webp/1*0qxXSoFzTIKpRqWWWIBt1w.png)

Now that we have Ann’s credentials, we should analyze if we can find more information about her e-mail changes.

![Figure 05: Wireshark SMTP Protocol](https://miro.medium.com/v2/resize:fit:720/format:webp/1*kxX2nt4L4mlUwnTDmSVCYA.png)

In the highlighted line, it’s possible to find the body of an e-mail message, that could be the person Ann has been trading e-mails with.

![Figure 06: Wireshark - E-mail](https://miro.medium.com/v2/resize:fit:640/format:webp/1*SydZ3oNPZa_OgrJZomE9Og.png)

Looking at the rest of the packet there’s more suggestive messages that indicates that this person could be Ann’s secret lover.

![Figure 07: Wireshark - Messages](https://miro.medium.com/v2/resize:fit:720/format:webp/1*30bHkNPQScbpMYRRBdTfuQ.png)

We can also find an attachment file at the end of the message.

![Figure 08: Wireshark - File Name](https://miro.medium.com/v2/resize:fit:720/format:webp/1*30bHkNPQScbpMYRRBdTfuQ.png)

By following the TPC stream and going back to the attachment information inside of the e-mail, we can find the code of the file, which according to the content-transfer, is encoded in base64.

![Figure 09: Wireshark - TCP Stream](https://miro.medium.com/v2/resize:fit:720/format:webp/1*DISAj77F8d8sKbovbH7iug.png)

In order to extract the file, we can take the code and put it into a decoder tool.

![Fire 10: Base64 to File - Base64 Guru](https://miro.medium.com/v2/resize:fit:720/format:webp/1*DpbzCy46OgIdSFrQSKPXUw.png)

Opening the file “application.docx” we have the place where Ann wants to meet.

![Figure 11: application.docx](https://miro.medium.com/v2/resize:fit:720/format:webp/1*hlIXBghci1Y9Y74w5QzWAQ.png)

Once you have the file, you can open the terminal and check out its MD5 hash by using the command certutil.

![Figure 12: application.docx MD5 Hash](https://miro.medium.com/v2/resize:fit:640/format:webp/1*1LOxvU4dE8cia5xl8S1fqg.png)

That way the challenge is completed! Thank you for reading.
