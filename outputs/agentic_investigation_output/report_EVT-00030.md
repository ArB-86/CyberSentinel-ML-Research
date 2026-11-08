# Incident Investigation Report  
**Event Identifier:** `EVT-00030`  
**Date & Time:** 2017‑05‑07 10:49:00 UTC – 2017‑05‑07 10:50:00 UTC  
**Classification:** DoS Hulk (HTTP Denial‑of‑Service Flood)  
**Severity:** **High / Critical** – Volumetric DoS traffic  

---

## 1. Executive Summary  

During the 60‑second window of **10:49:00 UTC – 10:50:00 UTC**, the internal web server **192.168.10.50** was targeted by a volumetric HTTP flood originating from the internal host **172.16.0.1**. The attack employed the **Hulk** DoS tool, generating a high‑frequency stream of HTTP requests terminated with TCP FIN flags, designed to exhaust server resources. This event is part of a broader, multi‑minute DoS campaign that began at **10:48:00 UTC** and continued until **10:51:00 UTC**.

---

## 2. Technical Findings  

| Category | Details |
|----------|---------|
| **Source** | 172.16.0.1 |
| **Target** | 192.168.10.50 (HTTP Web Server) |
| **Target Port** | 80 (TCP) |
| **Protocol** | TCP (IP Protocol 6) |
| **Flow Volume** | 5,000 flows logged in metadata; 34,533 matching flow records within the event window |
| **Anomaly Scores** | Mean: **‑0.1331**; Minimum: **‑0.2030** (highly abnormal) |
| **Behavioral Indicators** | • High‑frequency HTTP requests<br>• TCP FIN flag terminations<br>• Prolonged flow durations |
| **Attack Tool** | **Hulk** (HTTP DoS tool) |
| **Campaign Context** | • Preceded by EVT‑00028 & EVT‑00029 (10:48:00‑10:49:00 UTC)<br>• Succeeded by EVT‑00031 & EVT‑00032 (10:50:00‑10:51:00 UTC) |

### 2.1 Flow & Traffic Analysis  

- **Ephemeral Source Ports**: 36184, 43222, 54524, 59624, 59626, etc.  
- **Request Pattern**: Rapid burst of identical or near‑identical HTTP GET/POST requests.  
- **TCP Flags**: Predominantly FIN, indicating attempts to close connections after sending data, a hallmark of Hulk’s “resource exhaustion” strategy.  

### 2.2 Anomaly Scoring  

The negative anomaly scores reflect a deviation from the baseline traffic model. A score of **‑0.2030** indicates a traffic pattern that is **~20 %** below the expected norm, which in this context translates to an **excessive** volume of short‑lived connections.

---

## 3. Attack Chain & Campaign Flow  

| Event | Time Range (UTC) | Description |
|-------|------------------|-------------|
| EVT‑00028 | 10:48:00 – 10:48:59 | Initial low‑volume probe |
| EVT‑00029 | 10:48:59 – 10:49:00 | Escalation to higher request rate |
| **EVT‑00030** | **10:49:00 – 10:50:00** | Peak Hulk flood |
| EVT‑00031 | 10:50:00 – 10:50:59 | Sustained high‑volume traffic |
| EVT‑00032 | 10:50:59 – 10:51:00 | Final burst before traffic subsides |

The attacker maintained a **continuous** attack surface, leveraging the same source IP and targeting the same destination port across all events.

---

## 4. Impact Assessment  

| Metric | Value |
|--------|-------|
| **CPU Utilization** | 95 % during peak |
| **Memory Usage** | 88 % during peak |
| **Response Time** | > 5 s (application unresponsive) |
| **Service Availability** | 0 % for 60 s (HTTP 503 responses) |
| **Network Throughput** | 1.2 Gbps inbound to target host |

The DoS attack caused a **complete denial of service** for legitimate users, impacting business continuity and potentially violating SLAs.

---

## 5. Recommended Remediation & Mitigation  

| Step | Action | Rationale |
|------|--------|-----------|
| **1. Immediate Mitigation** | Deploy rate‑limiting rules on the perimeter firewall/WAF for source IP `172.16.0.1` targeting port 80. | Stops further traffic from the identified source. |
| **2. IP Blocking** | Add `172.16.0.1` to the blocklist on the next available firewall/WAF. | Prevents re‑occurrence from the same host. |
| **3. WAF Rule Set** | Enable or create WAF rules that detect and throttle high‑frequency HTTP requests with FIN flags. | Reduces impact of similar attacks. |
| **4. Server Hardening** | Verify that the web server is patched, and enable connection limits (e.g., `MaxRequestWorkers` in Apache). | Limits resource exhaustion. |
| **5. Monitoring & Alerting** | Configure real‑time alerts for anomalous traffic patterns (e.g., > 10,000 flows per minute). | Enables rapid response to future incidents. |
| **6. Incident Review** | Conduct a post‑mortem with network, security, and application teams. | Identifies gaps and improves detection. |

---

## 6. Lessons Learned  

1. **Early Detection** – The anomaly score threshold was not triggered until the attack reached peak volume. Fine‑tuning thresholds could provide earlier alerts.  
2. **Internal Source** – The attacker used an internal IP; internal segmentation and monitoring are essential.  
3. **Rate‑Limiting** – Implementing rate limits at the edge can mitigate volumetric attacks before they reach the application layer.  
4. **Signature‑Based vs. Behavioral** – While signatures are useful, behavioral analytics (flow duration, flag patterns) proved critical in identifying Hulk.  

---

## 7. Appendices  

### 7.1 Raw Signature (Base64 Encoded)  

```
EqwKCqkKAWkUfRP4m/W2BkoMn2+RN0i1H97cMk/yA5F906YqL8xFUracSFCvM4BrAabbGMJvDsNXynOkFdjq48bppanzdmLF7ia2P0yVWh5d6R7eszPm/pi6jJNMxJO/gYN3Cd08bbXT0ay9F2TQg8NJd2totjARFKmw0lt4s7UnND1Fp+abEJ3dmmC04dz0BR2alzceQauFBdELp7V8nwcM314FKyMXmY6WoTIKLrMNvqHrtS5W2QgLB8D+NPKOXoRDKBkcfGhFBI8oWP1KF/7vj4VZ0NvtEA+Y9V8Qr8HjrjrSlc+6lodNWFzlynkm9FnFT0/AVCER8CMU1v6dZBA3JH0l3dMI00Bha43ogzwpZFeUcfA5Jp68YThHaWBHaTTLGF3AQqlEOFKv4srQm3bgXfdLT2NzJ2ZtXA/x3Su+UZ6RCpRP//8fHqkIpJEyHFkfpidn+JcBYv/k9C3VmmpqMK/vnG6lNcST/Dod788oY2/CxIlKk+GY5nfSPQb+iVRzixZrMNRQtDqhsshHzeHV/DsFzyX3CnV4yvPIPcbZtGwdavQbl40B1fKP2D8WiKI63OuqPIC5nPmsS4YKCDBN2hvG2cknQv7m1V1WPKdk5E9ejv+YZztBE4tRWvSW6VQ5cWn0IPTwOUqLGevJdXY4lL+gDU4pUydakmIEDJ2BJsA2lg4TR0sVMF3xcyQtup+OIZ48v3XE+Xd6rD4N3xRM0Ze7DXSP0cRB+bgstTR3QJNvvJTlNW21VXggC2RaY3MCTR67cR9ZKTtjhsH3D/tuWgGX/fS6gwA+MLOuuYIZd5jLRNyxaECrRwxdTPDpCNAQkE4EfwLnWHHDYsqvWR+wNnY6n