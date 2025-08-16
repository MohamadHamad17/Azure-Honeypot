# Azure-SOC-Honeypot-AttackMAP's

<img width="1018" height="570" alt="Azure Honeypot Map" src="https://github.com/user-attachments/assets/6f4f3a79-2890-4f6e-8899-7d60e85bb4af" />

---

## 📌 Project Description and Project Architecture

This is my **Azure-Honeypot project**, which I built as a **live SOC-style environment** with over **1,000+ active members and devices**. I purposely left parts of the network open to the public so that I could capture both **legitimate user traffic** (from people on the same virtual network) and **malicious traffic** from bad actors on the internet.  

I used this setup to simulate what a real SOC team would see and respond to in an enterprise environment. By leveraging **Microsoft Sentinel**, **Log Analytics**, and **KQL queries**, I was able to collect logs, enrich them, and create **attack maps** that show where threats are coming from in real time.


<img width="1018" height="570" alt="Screenshot 2025-08-16 at 2 47 04 PM" src="https://github.com/user-attachments/assets/68866156-1bf1-4fc5-8a87-953bfd5ab787" />

---

## ⚙️ Tools & Technologies I Used

- **Microsoft Sentinel (SIEM):** where I built detections, hunting queries, and workbooks.  
- **Log Analytics Workspace:** the central hub for logs like Entra ID sign-ins, VM authentication events, Azure Activity, and network traffic.  
- **KQL (Kusto Query Language):** the language I used to query and shape log data into JSON outputs that power the maps.  
- **GeoIP enrichment:** I enriched raw IP addresses into geo-coordinates (latitude/longitude) so I could visualize the source of traffic globally.  

---

## 🌍 Attack Maps I Created

I designed interactive **world map visualizations** for the following scenarios. Each one pulls data directly from logs in real time:

- **Entra ID Authentication Success** → showing where valid logins to the tenant came from.  
- **Entra ID Authentication Failures** → highlighting brute-force and failed login attempts.  
- **Azure Resource Creation** → visualizing when and where resources were created.  
- **VM Authentication Failures** → tracking failed RDP/SSH login attempts against honeypot VMs.  
- **Malicious Traffic Entering the Network** → showing hostile traffic and scanning activity from bad actors.  

These dashboards give a clear picture of what’s happening in my environment at a glance.

---

## 📊 How I Built It

1. I logged into the **Azure Portal** and went to **Sentinel → Threat Management → Workbooks → Add Workbook**.  
2. I connected the workbook to my **Log Analytics Workspace**.  
3. I wrote **KQL queries** to pull authentication events, VM logs, and traffic data.  
4. I used JSON outputs with geo-coordinates to build **map visualizations**.  
5. I pinned the workbook to Sentinel so I could monitor activity like a live SOC dashboard.

---
## Entra ID (Azure) Authentication Success

This visualization shows all **successful Entra ID authentication attempts** into my environment. It helps me track where legitimate users are logging in from globally and confirm that activity aligns with expected regions. By mapping these logins, I can quickly spot unusual sign-ins from unexpected countries that might indicate account compromise.

**Query used to locate events:**
```kql
SigninLogs
| where ResultType == 0
| summarize LoginCount = count() by Identity, Latitude = tostring(LocationDetails["geoCoordinates"]["latitude"]), Longitude = tostring(LocationDetails["geoCoordinates"]["longitude"]), City = tostring(LocationDetails["city"]), Country = tostring(LocationDetails["countryOrRegion"])
| project Identity, Latitude, Longitude, City, Country, LoginCount, friendly_label = strcat(Identity, " - ", City, ", ", Country)
```
### Attack Map Vizulatiztion
<img width="1121" height="528" alt="Screenshot 2025-08-16 at 3 06 50 PM" src="https://github.com/user-attachments/assets/f2369181-9218-4ff7-83a9-6f3dcc37aafe" />

---
## Entra ID (Azure) Authentication Failures

This visualization highlights all **failed Entra ID authentication attempts**. It allows me to see where brute-force attacks or suspicious login attempts are coming from across the globe. By mapping failed sign-ins, I can quickly identify high-risk regions, repeated attempts from the same IPs, and patterns that may point to account takeover attempts.

**Query used to locate events:**
```kql
SigninLogs
| where ResultType != 0 and Identity !contains "-"
| summarize LoginCount = count() by Identity, Latitude = tostring(LocationDetails["geoCoordinates"]["latitude"]), Longitude = tostring(LocationDetails["geoCoordinates"]["longitude"]), City = tostring(LocationDetails["city"]), Country = tostring(LocationDetails["countryOrRegion"])
| order by LoginCount desc
| project Identity, Latitude, Longitude, City, Country, LoginCount, friendly_label = strcat(Identity, " - ", City, ", ", Country)
```
### Attack Map Vizulatiztion
<img width="1121" height="528" alt="Screenshot 2025-08-16 at 3 10 55 PM" src="https://github.com/user-attachments/assets/57313a2b-7aea-4bff-a471-ce3c0ac05047" />

---
## Azure Resource Creation
This visualization tracks all **Azure resource creation events** within my environment. It gives me visibility into when and where new resources are being deployed, helping to confirm expected activity while also flagging any unusual or unauthorized provisioning attempts that could indicate malicious behavior.

**Query used to locate events:**
```kql
// Only works for IPv4 Addresses
let GeoIPDB_FULL = _GetWatchlist("geoip");
let AzureActivityRecords = AzureActivity
| where not(Caller matches regex @"^[{(]?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}[)}]?$")
| where CallerIpAddress matches regex @"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
| where OperationNameValue endswith "WRITE" and (ActivityStatusValue == "Success" or ActivityStatusValue == "Succeeded")
| summarize ResouceCreationCount = count() by Caller, CallerIpAddress;
AzureActivityRecords
| evaluate ipv4_lookup(GeoIPDB_FULL, CallerIpAddress, network)
| project Caller, 
          CallerPrefix = split(Caller, "@")[0],  // Splits Caller UPN and takes the part before @
          CallerIpAddress, 
          ResouceCreationCount, 
          Country = countryname, 
          Latitude = latitude, 
          Longitude = longitude, 
          friendly_label = strcat(split(Caller, "@")[0], " - ", cityname, ", ", countryname)
```

### Attack Map Vizulatiztion
<img width="1121" height="528" alt="Screenshot 2025-08-16 at 3 14 15 PM" src="https://github.com/user-attachments/assets/78f6a23e-2d63-49ba-b3a6-6268b9d77caf" />

---

## VM Authentication Failures

This visualization captures all **failed authentication attempts against my virtual machines** (such as RDP or SSH logins). It shows where brute-force activity is coming from and helps me distinguish between normal failed logins from users on the same virtual network versus malicious attempts from external bad actors scanning and attacking exposed endpoints.

**Query used to locate events:**
```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
DeviceLogonEvents
| where ActionType == "LogonFailed"
| order by TimeGenerated desc
| evaluate ipv4_lookup(GeoIPDB_FULL, RemoteIP, network)
| summarize LoginAttempts = count() by RemoteIP, City = cityname, Country = countryname, friendly_location = strcat(cityname, " (", countryname, ")"), Latitude = latitude, Longitude = longitude;
```

### Attack Map Vizulatiztion
<img width="1121" height="528" alt="Screenshot 2025-08-16 at 3 15 54 PM" src="https://github.com/user-attachments/assets/22a22491-ed23-429e-9f74-ba5af9061b19" />

---
## Malicious Traffic Entering the Network
This visualization shows **malicious or suspicious traffic targeting my environment**. By mapping hostile IPs attempting to probe or attack exposed services, I can quickly identify global attack origins and patterns. This helps demonstrate how devices open to the public internet attract constant scanning and intrusion attempts from bad actors worldwide.

**Query used to locate events:**
```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let MaliciousFlows = AzureNetworkAnalytics_CL 
| where FlowType_s == "MaliciousFlow"
//| where SrcIP_s == "10.0.0.5" 
| order by TimeGenerated desc
| project TimeGenerated, FlowType = FlowType_s, IpAddress = SrcIP_s, DestinationIpAddress = DestIP_s, DestinationPort = DestPort_d, Protocol = L7Protocol_s, NSGRuleMatched = NSGRules_s;
MaliciousFlows
| evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)
| project TimeGenerated, FlowType, IpAddress, DestinationIpAddress, DestinationPort, Protocol, NSGRuleMatched, latitude, longitude, city = cityname, country = countryname, friendly_location = strcat(cityname, " (", countryname, ")")
```
### Attack Map Vizulatiztion
<img width="1121" height="528" alt="Screenshot 2025-08-16 at 3 17 46 PM" src="https://github.com/user-attachments/assets/086e388f-2851-4c42-a627-fefd61a496ef" />

---


## Why I Did This?

- I wanted to **simulate a real SOC environment** and practice with the same tools used in enterprise security.  
- By exposing devices to the public internet, I was able to capture actual **malicious activity** while still monitoring **legitimate logins**.  
- This gave me experience working with **Sentinel, KQL, and log enrichment** while seeing how attackers operate in the wild.  
- The project shows how I can go from **raw logs → analysis → visualization** to support threat hunting and incident response.  

---

## 🔮 What’s Next

- Expanding the honeypot to include more services for a wider attack surface.  
- Adding **Threat Intelligence feeds** to correlate known-bad IPs directly in my dashboards.  
- Automating incident response with **Logic Apps** playbooks.  
- Integrating **Microsoft Defender for Endpoint** alerts into the visualization layer.  

---

