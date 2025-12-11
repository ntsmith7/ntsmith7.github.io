---
title: "Hybrid-Cloud Security Lab"
date: 2025-11-15
tags: ["Kubernetes", "K3s", "Juice Shop", "Falco", "Detection Engineering"]
summary: "A persistent K3s and Juice Shop environment designed to simulate real-world attack vectors, lateral movement, and container escape techniques for detection engineering."
---

### The Objective
Standard penetration testing labs often lack the complexity of modern orchestration layers. I architected this environment to move beyond simple web-app exploitation and focus on the **post-exploitation telemetry** of containerized environments. The goal was to generate valid logs for lateral movement attempts between pods and verify if default Falco rulesets would catch a standard `privileged` container escape.

### Infrastructure as Code
The lab runs on a 3-node K3s cluster managed via Ansible. I deployed OWASP Juice Shop using a custom Helm chart that deliberately weakens security contexts to allow for specific attack paths.

**Cluster Configuration (`inventory.yml` snippet):**
```yaml
k3s_cluster:
  children:
    server:
      hosts:
        master-01:
          ansible_host: 192.168.20.10
          # Taint master to prevent workload scheduling
          node_taints: ["CriticalAddonsOnly=true:NoExecute"]
    agent:
      hosts:
        worker-01:
          ansible_host: 192.168.20.11
        worker-02:
          ansible_host: 192.168.20.12