# SOC145 RANSOMWARE DETECTED 
## LETS DEFEND PLATAFORM
<h4> BY Luis Sanguano (AngelXS) </h4>

[![letsdefend.png](https://i.postimg.cc/7b8LpxvY/letsdefend.png)](https://postimg.cc/PvyhDnrB)

In the “Practice” tab you can find the case “SOC145 - Ransomware Detected” to be solved, it has a Critical severity: 

![imagen](https://github.com/user-attachments/assets/9870f999-ffd5-4296-8e42-0169fd268986)

[![Captura-de-pantalla-2024-08-25-153950.png](https://i.postimg.cc/qvHtFG0X/Captura-de-pantalla-2024-08-25-153950.png)](https://postimg.cc/56pNYLX6)

## Description of the alert 
The alert has the following detailts that we need to solve the challenge:

![imagen](https://github.com/user-attachments/assets/4cda9709-20e5-45e4-82e6-f777b104d7a2)

![imagen](https://github.com/user-attachments/assets/6af5fb04-4b73-4e19-9ba5-fd8aeb2f26cf)

I personally prefer to clean up the details and highlight those that are useful to me for the respective analysis: 

![imagen](https://github.com/user-attachments/assets/08e0bc0a-e9e4-42f8-8a7e-7229b70a82f3)

In the event details you can see that the source hostname is “MarkPRD”, this is an important clue, since from the ENDPOINT SECURITY option, you can search for the Hostname and find the machine related to the event.

![imagen](https://github.com/user-attachments/assets/10cf7917-9111-434f-a1e6-b270bd874a77)

![imagen](https://github.com/user-attachments/assets/e3e82280-37e0-4a34-959c-d268cf403fc4)

In the details you can see different options, we are going to analyze the “Process List” to verify event by event what the user has done and in this way find information that is useful to us:

![imagen](https://github.com/user-attachments/assets/9c4e3168-2647-436d-9f94-38afb33a1ae2)

We found several interesting details in the executable file **ab.exe** with the MD5 hash **0b486fe0503524cfe4726a4022fa6a68** this hash is the same as the one presented in the event details (figure highlighted in yellow), it is an interesting clue, because we found the file that could generate the alert:

![imagen](https://github.com/user-attachments/assets/d6b9957d-20b5-4074-9274-0cf54e634284)

If we analyze this hash with the help of VirusTotal (https://www.virustotal.com) we can see that it is a malicious file: 

![imagen](https://github.com/user-attachments/assets/195f6149-7658-494e-b8b5-b29046975328)

![imagen](https://github.com/user-attachments/assets/a92d4f1f-2c40-479f-b0e4-7ec199e76907)

We can see that the found hash is already detected as ranmsomware:

![imagen](https://github.com/user-attachments/assets/a4775834-85f9-4205-a273-ee51c1d6dec7)

In the details related to this hash you can find that the file name ab.exe has been sent for analysis before:

![imagen](https://github.com/user-attachments/assets/88729a0f-9c81-4883-b670-bf8b1f282432)

The DLLs listed below are common in Windows and can be used by ransomware or any type of malware to execute various functions. Here's how some of these DLLs can be related to typical ransomware behavior:

    **ADVAPI32.dll:** Contains functions to access Windows APIs, including account management, services, and cryptographic functions. Ransomware could use this DLL to interact with the Windows Registry, manipulate services, and perform cryptographic operations, such as file encryption.

    **CRYPT32.dll:** This DLL provides cryptographic services, such as data encryption and decryption, and is key in implementing security in applications. Ransomware generally uses it to encrypt the victim's files.
    KERNEL32.dll: It is one of the most fundamental DLLs in Windows, providing access to memory, processes, and file operations. Although not specifically designed for malicious activities, ransomware can use functions in KERNEL32.dll to read, write, and encrypt files.

    **SHELL32.dll:** Provides functions for the Windows user interface, such as opening files and directories. Ransomware could use this DLL to modify the user interface or change icons and messages, which can be part of the visual extortion process.

    **NETAPI32.dll:** Includes network-related functions, especially in Windows network environments. Some ransomware uses it to spread through networks via vulnerabilities or malicious file sharing.

    **OLEAUT32.dll and ole32.dll:** These DLLs are related to OLE (Object Linking and Embedding) Automation. The ransomware can use them to interact with applications that support OLE to perform complex automation or file and data manipulation tasks.

In summary, ADVAPI32.dll, CRYPT32.dll, KERNEL32.dll, SHELL32.dll, NETAPI32.dll, OLEAUT32.dll, and ole32.dll are the DLLs most closely related to typical ransomware activities, although this does not mean that the others cannot be used at some point by malicious software to achieve its goals.

![imagen](https://github.com/user-attachments/assets/ac955f8b-8dca-478b-8757-e20ca7dc2659)

We can presume that the threat indicator is related to a malfunction of the anti-virus or the anti-virus was disabled when the user executed the .exe, therefore we answer the following:

![imagen](https://github.com/user-attachments/assets/2267ae1d-1e39-4fb7-a63a-673caf771ae4)

You can see that the Device Action is found as “allowed” and the detected malware was not quarantined, therefore it responds as “not quarantined”:

![imagen](https://github.com/user-attachments/assets/a16cc841-aa78-4175-afb6-6264c6f60428)

***Analyze Malware***

At this point, we already know that it is a malicious file, but it is necessary to analyze the ab.exe file with a sandbox, in this case we will use VMRAY:

![imagen](https://github.com/user-attachments/assets/94516705-07fc-4d82-9351-8536aef6bbcb)

We set up the details:

![imagen](https://github.com/user-attachments/assets/96e7348f-eb69-400a-b178-69fe08325caf)

We note that VMRAY lists it as “MALICIOUS”:

![imagen](https://github.com/user-attachments/assets/aa849f49-a56d-470b-a6ad-908b3d362e03)

![imagen](https://github.com/user-attachments/assets/11ad2e3d-eb3e-4c8b-9a2d-f3cece9399eb)

VMRAY threat identifiers: user data modification (appends the same extension to many filenames) behavior of ranmsomware. 

![imagen](https://github.com/user-attachments/assets/68f4d810-ab8b-4dee-bdeb-740cdd917d7c)

The file is ***MALICIOUS***.

The next question is about log management and check if the C2 address accessed. 

![imagen](https://github.com/user-attachments/assets/020f21db-511c-4477-a5fd-7097b2fab568)

Search by IP: ***172.16.17.88****

![imagen](https://github.com/user-attachments/assets/0f05938c-142f-4351-aaa7-3dd3d3d79a9f)

Remember that the file hash was ***0b486fe0503524cfe4726a4022fa6a68***:

First check de IP on AbusedIp (https://www.abuseipdb.com) app: 

![imagen](https://github.com/user-attachments/assets/2c126077-c8b5-42eb-baea-6b1310a26ec3)

![imagen](https://github.com/user-attachments/assets/2ccd1a5e-d5b8-4671-b5f5-fe63c1cec65e)

The IPs are clean. Futhermore, check the raw log and details (Paren Process MD5) you need to chech de MD5 of ab.exe: 

![imagen](https://github.com/user-attachments/assets/2748db13-7c1f-471e-9e90-f57ec7b6ae2f)

we need to add “ARTIFACTS” the value is the MD5 ***0b486fe0503524cfe4726a4022fa6a68*** we place the MD5 type and a description as shown below: 

![imagen](https://github.com/user-attachments/assets/3ef00edf-3d31-4de1-8aa3-91c0e127de4a)

![imagen](https://github.com/user-attachments/assets/9e6743e0-dcd0-4d4f-8f16-fc56b09dcf71)

Finally close alert as ***TRUE POSITIVE***: 
![imagen](https://github.com/user-attachments/assets/5ac0e3b5-8444-4479-a8e1-0030680797bb)
![imagen](https://github.com/user-attachments/assets/bcbbc9da-e0a6-4ae9-a52b-b809cb49b6b8)
![imagen](https://github.com/user-attachments/assets/88daecf2-565b-4c50-8777-c6a38fcdb4e5)

<h1>Extra Information</h1>

As additional information I show you the execution of the ab.exe file in the VMRay sandbox in different versions of the Windows operating system:
** Windows 10 **
![imagen](https://github.com/user-attachments/assets/79040fb8-6193-492f-b3b3-cfbe9affa805)
![imagen](https://github.com/user-attachments/assets/32ff5552-a7f2-426f-a4f9-622235bb3844)
![imagen](https://github.com/user-attachments/assets/f6a900d2-9bb7-4527-b3b9-49fc878e6a43)


** Windows 7 **
![imagen](https://github.com/user-attachments/assets/653ba8e8-0a9c-44f5-a5ca-6ae05947f8bd)
![imagen](https://github.com/user-attachments/assets/32975e46-d29b-4c71-be32-890d346a0523)
![imagen](https://github.com/user-attachments/assets/804d6d12-f6c3-49da-9d17-cd69852162ba)
![imagen](https://github.com/user-attachments/assets/40b2cdee-0e50-480d-86fb-c1670bea02db)
![imagen](https://github.com/user-attachments/assets/615d3bfc-94cc-4841-9e78-ac7f9c691c3f)
![imagen](https://github.com/user-attachments/assets/828c5d74-c3f4-40f6-8a65-59559e1d6ffc)
![imagen](https://github.com/user-attachments/assets/6d076d92-918f-44c4-843a-dac8aaf7b528)







