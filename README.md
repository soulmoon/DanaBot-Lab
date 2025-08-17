# DanaBot Lab - CyberDefenders

**Category:** Network Forensics  
**Tactics:** Execution, Command and Control  
**Tools:** Wireshark, VirusTotal, ANY.RUN, Network Miner  

---

## 📝 Scenario
The SOC team has detected suspicious activity in the network traffic, revealing that a machine has been compromised. Sensitive company information has been stolen. Your task is to use Network Capture (PCAP) files and Threat Intelligence to investigate the incident and determine how the breach occurred.

---

## ❓ Questions & Answers

**Q1: Which IP address was used by the attacker during the initial access?**  
>> 62.173.142.148
<img width="940" height="508" alt="image" src="https://github.com/user-attachments/assets/41d53bc2-884c-497e-9196-ab6745f80e94" />
 

**Q2: What is the name of the malicious file used for initial access?**  
>> allegato_708.js  
<img width="940" height="476" alt="image" src="https://github.com/user-attachments/assets/22df7100-70d0-4d44-bb3a-fe7ec61af11a" />

**Comment:**  
If you see a file named login.php but its MIME type is application/octet-stream, that usually means:  
1. It’s not actually a PHP script  
   - A normal PHP file should have MIME type like text/x-php or text/plain when inspected with file or web servers.  
   - application/octet-stream is a generic “binary file” type.  
2. Possibilities:  
   - The file might be corrupted or encoded/encrypted.  
   - It could be a malicious payload disguised as login.php. Attackers often drop .php files with binary content to bypass detection.  
   - Sometimes, it’s just compressed/packed content (e.g., base64, gzipped, or compiled payload) that requires unpacking.  

**Q3: What is the SHA-256 hash of the malicious file used for initial access?**  
>> 847b4ad90b1daba2d9117a8e05776f3f902dda593fb1252289538acf476c4268  
<img width="940" height="757" alt="image" src="https://github.com/user-attachments/assets/09d98563-88f7-470e-b2cb-8403dbfa2f99" />

**Q4: Which process was used to execute the malicious file?**  
>> wscript.exe  
<img width="940" height="536" alt="image" src="https://github.com/user-attachments/assets/8f489f25-4477-4a32-b2be-c0fa43507ac5" />

**Q5: What is the file extension of the second malicious file utilized by the attacker?**  
>> .dll  
<img width="940" height="499" alt="image" src="https://github.com/user-attachments/assets/7a0f0b77-f5c6-470c-8f96-94e8803e959e" />

**Q6: What is the MD5 hash of the second malicious file?**  
>> e758e07113016aca55d9eda2b0ffeebe  
<img width="733" height="214" alt="image" src="https://github.com/user-attachments/assets/f2f3f702-c34f-4c3c-a2a5-87b8fd59a393" />

---

## 🛠 Filters & Commands Used

| Question | Tool / Command | Filter / Command Syntax |
|----------|----------------|------------------------|
| Q1 | Wireshark | `_ws.col.protocol == "DNS"` |
| Q2 | Wireshark | `_ws.col.protocol == "HTTP"` |
| Q3 | Kali Linux | `sha256sum <Maliciousfilename>` |
| Q6 | Kali Linux | `md5sum <filename>` |
| Q3       | `Export HTTP Object: File>Export Objects>HTTP`<br>`# sha256sum <Maliciousfilename>` | Export the malicious file and calculate its SHA-256 hash using Linux command |
| Q6       | `Export HTTP Object: File>Export Objects>HTTP`<br>`# md5sum <filename>` | Export the second malicious file and calculate its MD5 hash |

---

