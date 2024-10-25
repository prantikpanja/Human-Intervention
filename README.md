# Human-Intervention

In this project, we considered 100 APT samples and performed an analysis with Cuckoo Sandbox. 

## Source of Malware sample
https://github.com/cyber-research/APTMalware

## Sandbox used
Cuckoo sandbox https://cuckoosandbox.org/

## Ananysis 
We've considered billow activity as an event while analysing the APT malware.


| Activity Type  | Activity     |
| ------------- | ------------- |
| Registry access  |  RegOpenKeyExA |
| Registry access  |  RegQueryValueExA |
| Registry access  | RegCloseKey  |
| Registry access  | RegSetValueExA  |
| Registry access  | RegCreateKeyA  |
| File access  | CreateFileA  |
| File access  | OpenProcess  |
| File access  | ReadFile  |
| File access  |  WriteFile |
| Process creation/termination  | CreateProcessA |
| Process creation/termination  | OpenProcess |
| Process creation/termination  | TerminateProcess |
| Process creation/termination  | ShellExecuteExA |
| Sensitive privilege use | CreateProcessAsUserA |
| Sensitive privilege use | win_token |
| Sensitive privilege use | escalate_priv |
| Network access | HttpSendRequestA |
| Network access | HttpOpenRequestA |
| Network access | HttpAddRequestHeadersA |
| Network access | InternetOpenA |
| Network access | WSAStartup |
| Network access | closesocket |


We've assigned a score based on our scoring mechanism and created a final score for an APT sample.


