---
title: Tips & Resources for Email Analysis
author: 0wlexe
date: 2023-1-1 20:55:00 +0800
categories: [Articles, Cybersecurity]
tags: [File Analysis, Phishing]
pin: false
image:
  path: /assets/img/posts/email-resources.png
  alt: Tips and resources on how to have a better understanding of phishing attacks using e-mail messages.
---

## Summary:
At the present moment, phishing is still considered one of the most frequent ocurrencies of fraudulent activity on the Internet.

More often than not, an email message containing a link or an attachment can lead to severe losses for their aimed victims including the data breach of sensitive information and identity theft.

According to [IBM’s 2022 Cost of a Data Breach Report](https://www.ibm.com/reports/data-breach), “In 2022, the most common initial attack vectors were compromised credentials at 19% of breaches and phishing at 16% of breaches.” On average, the costliest initial attack vector was phishing at USD 4.91 million, **followed by business email compromise at USD 4.89 million.**

With that in mind, this article contains important tips and tools to help both cybersecurity analysts and general users on how to detect possible threats associated with phishing e-mails.

## Spoofing & how to detect a Suspicious E-mail

Attackers can send emails on behalf of someone else, as the e-mail messages do not necessarily have an authentication mechanism. This kind of technique is called **spoofing**, and is used to make the user believe that the incoming email is reliable.

An example of suspicious e-mail can be seen as below, where the sender domain belongs to a public address anyone can have *(‘@gmail.com’)*, and not a corporative e-mail *(‘@paypal.com’).*

![Figure 01 - Example of suspicious e-mail. source: pickr](https://miro.medium.com/v2/resize:fit:720/format:webp/0*6wrXySpaq6kqgSvT.jpeg)

A common technique threat actors have is to perform phishing attacks using mostly free, and legal platforms. Such as:

- **Services that offer Cloud Storage such as Google and Microsoft:** Attackers try to use Google / Microsoft drive addresses that seem harmless to the user by uploading harmful files onto the drive.
- **Free subdomains services such as Google, Wordpress, Blogspot, Wix, GoDaddy:** Threat actors try to deceive security products and analysts by creating a free subdomain from these services. Since whois information cannot be searched as a subdomain, it can be seen that these addresses were taken in the past and belongs to the actual institutions.
- **Form applications:** Services are available that allow free form creation. Since the domain is harmless under normal conditions, it can pass on to the user without getting stuck on antivirus software. Google Forms is an example of these services. When looking at whois information, the domain can be seen to be Google, so the attacker can mislead further analysts.

## Structure of an Email Header
Before learning how to conduct an email analysis, it is important that we know how the structure of an e-mail header works.

- **From -** The sender’s address;
- **To -** The receiver’s address, including CC and BCC;
- **Date -** Timestamp, when the email was sent;
- **Subject -** The subject of the email;
- **Return Path -** The return address of the reply, a.k.a. **“Reply-To”.** If you reply to an email, the reply will go to the address mentioned in this field;
- **Domain Key and DKIM Signatures -** Email signatures are provided by email services to identify and authenticate emails;
- **SPF -** Shows the server that was used to send the email. It will help to understand if the actual server is used to send the email from a specific domain;
- **Message-ID -** Unique ID of the email;
- **MIME-Version -** Used MIME version. It will help to understand the delivered “non-text” contents and attachments;
- **X-Headers -** The receiver mail providers usually add these fields. Provided info is usually experimental and can be different according to the mail provider;
- **X-Received -** Mail servers that the email went through;
- **X-Spam Status -** Spam score of the email;
- **X-Mailer -** Email client name.

## Important Email Header Fields for Quick Analysis
Questions to Ask / Required Checks and Evaluations:

- Do the “From”, “To”, and “CC” fields contain valid addresses? **Having invalid addresses is a red flag.**
- Are the “From” and “To” fields the same? **Having the same sender and recipient is a red flag.**
- Are the “From” and “Return-Path” fields the same? **Having different values in these sections is a red flag.**
- Was the email sent from the correct server? **The Email should have come from the official mail servers of the sender.**
- Does the “Message-ID” field exist, and is it valid? **Empty and malformed values are red flags.**
- Do the hyperlinks redirect to suspicious/abnormal sites? **Suspicious links and redirections are red flags.**
- Do the attachments consist of or contain malware? **Suspicious attachments are a red flag. File hashes marked as suspicious/malicious by sandboxes are also a red flag.**

## Tools to use During an Analysis
### Email Client Apps

One of the fastest ways to see the visual contents of an “.eml” file is by opening it directly on an e-mail client like Thunderbird or Outlook.

Althought it’s a good way to get the visuals for your report, **it’s not reccomended to open such files in your desktop machine.** You can always download an e-mail client on a virtual machine instead or use text editors to see its content.

![Figure 02 - Example of phishing e-mail open on Thuderbird](https://miro.medium.com/v2/resize:fit:720/format:webp/1*udz7fhMA8Cu5hxRt8u3lpw.png)

### Text Editors
You can use a text editor of your own choice (Vim, Nano, Sublime, Visual Studio, EmEditor..) to view email files without opening and executing any of the linked attachments/commands.

#### [emlAnalyzer](https://github.com/wahlflo/eml_analyzer)

Text editors are helpful in analysis, but there are some tools that can help you to view the email details in a clearer format.

We can use the **“emlAnalyzer”** tool to view the body of the email and analyze the attachments. The emlAnalyzer is a tool designed to parse email headers for a better view and analysis process.

It can be used to show the headers, body, embedded URLs, plaintext, HTML data, and attachments. The sample usage query is explained below.

Query Details Explanation
```bash
    emlAnalyzer: Main command
    -i: File to analyse
    -i /path-to-file/filename
    -header: Show header
    -u: Show URLs
    -text: Show cleartext data
    -extract-all: Extract all attachments

    Note: Remember, you can either give a full file path or navigate to the required folder using the “cd” command.
```
An example of usage of the tool can be seen as below.

![Figure 03 - Usage of the emlAnalyzer](https://miro.medium.com/v2/resize:fit:720/format:webp/1*ZR7kZU0JSTjyqZWgEQex1A.png)

#### [PhishTool](https://www.phishtool.com/)
PhishTool is another useful tool for the automation of the analysis process, as it collects the necessary information — headers, body, embedded URLs, plaintext, HTML attachments… of selected .eml files in a way that’s easier for the comprehension.

![Figure 04 - PhishTool website](https://miro.medium.com/v2/resize:fit:720/format:webp/1*LFdf8sNX1zwm1vp0gxiQZg.png)

An example of usage of the tool can be seen as below, after registering on the platform from PhishTool.

![Figure 05 - Example of usage — PhishTool](https://miro.medium.com/v2/resize:fit:720/format:webp/1*xDUOx8js8I2ZaC-jl8QAQw.png)


## Open Source Intelligence (OSINT)
Additionally, you can use some Open Source Intelligence (OSINT) tools to check email reputation and enrich the findings. You can visit the given sites below and do a reputation check on the sender address and the address found in the return path.

#### [MxToolbox](https://mxtoolbox.com/)
The MX Record Lookup tool is an online application that lets you query DNS servers and get instant results. Mail Exchanger or MX lookups are used to determine the MX records associated with a domain, it can also be used to check out whether a domain is blacklisted or not.

![Figure 06 - MxToolbox](https://miro.medium.com/v2/resize:fit:720/format:webp/1*ApkbwQBjB-yR351DysTgdA.png)

#### [emailrep.io](https://emailrep.io/)
Tool used to detect targeted phishing attacks and e-mail reputation.

![Figure 07 - Simple Email Reputation](https://miro.medium.com/v2/resize:fit:720/format:webp/1*hyw8l2nzKqa2pKSDIk0VtA.png)

#### [Epieos](https://epieos.com/)
Tool for the gathering of information of accounts linked to an e-mail address **(can be efficient with ‘@gmail.com’ addresses).**

![Figure 08 - Epieos](https://miro.medium.com/v2/resize:fit:720/format:webp/1*04Nm8wOGC2-avS6ysCThFw.png)

#### [VirusTotal](https://www.virustotal.com/gui/)
A service that provides a cloud-based detection toolset and sandbox environment. It can be used to collect indicators of compromise, and static analysis of suspicious files.

![Figure 09 - VirusTotal](https://miro.medium.com/v2/resize:fit:720/format:webp/1*tNWN3ldo0faR51JLnYI0zg.png)

#### [Hybrid Analysis](https://www.hybrid-analysis.com/)
An alternative sandbox environment for VirusTotal, it detects possible IOCs, TTPs and gives a static analysis of malicious files.

![Figure 10 - HybridAnalysis](https://miro.medium.com/v2/resize:fit:720/format:webp/1*zp4lpiDUXwfOvePvtBv_1Q.png)

#### [InQuest Labs](https://labs.inquest.net/)
A service that provides network and file analysis by using threat analytics.

![Figure 11 - InQuest Labs](https://miro.medium.com/v2/resize:fit:720/format:webp/1*9OIiw3WaJ0iP0px_b2YQ4g.png)

#### [IPinfo.io](https://ipinfo.io/)
A service that provides detailed information about an IP address by focusing on geolocation data and service provider.

![Figure 12 - iPinfo.io](https://miro.medium.com/v2/resize:fit:720/format:webp/1*KN6A_vqfzPYpg0RSv3DrjQ.png)

#### [Talos Reputation](https://talosintelligence.com/reputation_center/)
An IP reputation check service provided by Cisco Talos.

![Figure 13 - Talos Reputation](https://miro.medium.com/v2/resize:fit:720/format:webp/1*8lhWWRPiCOnkGXxOYS2iLA.png)

#### [Urlscan.io](https://urlscan.io/)
A service that analyses websites by simulating regular user behaviour.

![Figure 14 - Urlscan.io](https://miro.medium.com/v2/resize:fit:720/format:webp/1*AHbVnfd84TThZeYRUJNEJQ.png)

#### [Browserling](https://www.browserling.com/)
A browser sandbox used to test suspicious/malicious links.

![Figure 15 - Browserling](https://miro.medium.com/v2/resize:fit:720/format:webp/1*cA9XAzBVesuT-Eybpv-W0A.png)

#### [Wannabrowser](https://www.wannabrowser.net/)
Another browser sandbox used for the testing of suspicious/malicious links.

![Figure 16 - Wannabrowser](https://miro.medium.com/v2/resize:fit:720/format:webp/1*7na00ziVadnJAoK6gBARzQ.png)

#### [AbuseIPDB](https://www.abuseipdb.com/)
AbuseIPDB is a project dedicated to helping combat the spread of hackers, spammers, and abusive activity on the internet. It can be useful to see and send abuse reports related to certain IP or Domain Addresses.

![Figure 17 - AbuseIPDB](https://miro.medium.com/v2/resize:fit:720/format:webp/1*lCKKG97MHUEsGjxHoJPUfQ.png)

## Example of Analysis

After getting to know most used concepts and tools, we can finally analyze the contents of an e-mail header.

![Figure 18 - Sample of suspicious email by LetsDefend](https://miro.medium.com/v2/resize:fit:720/format:webp/1*_UcmGY8Q6RV61vvJJVQc0g.png)

### Points of Attention

- Both the **Reply-to** and **Return-Path** of the sender adress contains different e-mail addresses;

![Figure 19 - Example of detection using PhishTool](https://miro.medium.com/v2/resize:fit:640/format:webp/1*e7fSHDf-EgGH2jV-Qq6qhw.png)

![Figure 20 - Example of detection in text editors (VScode)](https://miro.medium.com/v2/resize:fit:640/format:webp/1*oBdXLD3dUz7EmS00U2M7tA.png)

- The IP Address of the sender is **222.227.81.181**, and the message date (when it was sent) is **Monday - 21 of February, 2022;**

![Figure 21 - IP Address of the sender and date](https://miro.medium.com/v2/resize:fit:720/format:webp/1*tSIIytJdCpm4FMgabecLpA.png)

- The IP address ‘222.227.81.181’ is from **Japan**, under the domain **“kddi.ne.jp”;**

![Figure 22 - Information from the IP address](https://miro.medium.com/v2/resize:fit:720/format:webp/1*pCr3gp_WP0wz_cdj57zOvA.png)

Looking up *“KDDI Corporation”,* we can tell it is a possible legitimate service being useed by third parties.

![Figure 23 - Reserach information about the “KDDI Corporation”](https://miro.medium.com/v2/resize:fit:720/format:webp/1*JzfYxKns0YFFk1DBcdjJMA.png)

We can also search for information about the DNS address of the sender: *“snd01105-jc.im.kddi.ne.jp”;*

![Figure 24 - DNS Address of the sender](https://miro.medium.com/v2/resize:fit:640/format:webp/1*KIYSqlJvPAsKasTBLOz4zw.png)

It’s possible to find publications on the forums *“romancescam”* and *“scamsurvivors”* relating spam mails from that same DNS address.

![Figure 25 - Reserach of informations about the DNS Address](https://miro.medium.com/v2/resize:fit:720/format:webp/1*_6rDMipRJPxKBYTVmw9bBA.png)

With that we can confirm more suspicious messages were sent from the DNS Address **“snd01105-jc.im.kddi.ne.jp”** also using the following modus operandi:
- Reply-to is different from the Return-Path listed;
- “KDDI Corporation” is also the provider of the Return-path;
- Message is also under the pretext of a person who is sick, dying, and needs someone else to do “good deeds” with their money.

![Figure 26 - Publication from the forum “ScamSurvivors” — an online board for scam reports](https://miro.medium.com/v2/resize:fit:720/format:webp/1*itnj-37y4rtBe7_d8U7tZg.png)

- There‘s no malicious attachments related to that e-mail and static analysis tools couldn’t really detect any possible threat;

![Figure 27 - Analysis of the suspicious e-mail from VirusTotal](https://miro.medium.com/v2/resize:fit:720/format:webp/1*Gb9SlS26tQYYCeR_7C85HQ.png)

![Figure 28 - Analysis of the suspicious e-mail from HybridAnalysis](https://miro.medium.com/v2/resize:fit:720/format:webp/1*m6teBV8FORjBEbJCRd68Fg.png)

- The suspicious IP Address ‘222.227.81.181’ has also been reported a total of 29 times from 18 distinct sources on AbuseIPDB, mostly as a detected spam.

![Figure 29 - AbuseIPDB reports on the IP 222.227.81.181](https://miro.medium.com/v2/resize:fit:720/format:webp/1*_R_vU8UFFQP24546gS5mBQ.png)

## Conclusion of Analysis

Although no malicious attachments or links were found, the information that the **‘Reply-To’** email address **‘mrs.dara@daum.net’** is inconsistent with the **‘From’** e-mail **‘mrs.dara@jcom.home.ne.jp’** is suspicious.

When attempting to persuade a phishing target to respond, attackers often provide a different ‘Reply-To’ email address whilst spoofing a legitimate ‘From’ email address.

An unsuspecting target might reply to the phishing email believing they are replying to the email address shown prominently in their email client, when the response is actually being sent to the ‘Reply-To’ email address.

This could be a **social engineering** tactic to get financial information from the victim under the assumption they would actually receive the money. With a quickly research, it was also possible to find scam reports associated with the same DNS address, which concludes the sender of the message should not be trusted.

### References:

- *[TryHackMe: Advent of Cyber 2022 - Day 6: E-mail Analysis](https://tryhackme.com/room/adventofcyber4)*
- *[LetsDefend - Phishing Email Analysis](https://app.letsdefend.io/training/lessons/phishing-email-analysis)*
- *[Phishing Attacks: A Recent Comprehensive Study and a New Anatomy](https://www.frontiersin.org/articles/10.3389/fcomp.2021.563060/full)*
- *[Examples of Phishing Email: 20 Emails That Don’t Look Like It](https://www.aura.com/learn/phishing-email-examples#3.-Suspicious-activity-notice)*

