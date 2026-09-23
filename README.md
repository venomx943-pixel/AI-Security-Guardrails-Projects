# AI-Security-Guardrails-Projects

A robust, modular, and low-latency AI security framework engineered to protect Large Language Model (LLM) deployments against prompt injections, deep semantic evasions, and data exfiltration leaks.

## 🛡️ Architecture Overview

This framework implements a **Defense-in-Depth** strategy across three critical pipeline layers, strictly enforcing the **Fail-Closed** security principle to ensure absolute system integrity under any unexpected conditions.

### 1. Core Input Guardrail (`Input Shield`)
* **Purpose:** Acts as the primary entry checkpoint.
* **Key Mechanisms:**
  * **Text Normalization:** Neutralizes evasion tactics such as hidden whitespaces and character obfuscation.
  * **Signature Scanning:** Detects and blocks malicious prompt injections and Jailbreak patterns (e.g., DAN-style exploits) using optimized regular expressions.

### 2. Advanced Intent & Encoding Guard (`Deep Intent Shield`)
* **Purpose:** Detects psychological, structural, and encoded manipulation attempts.
* **Key Mechanisms:**
  * **Encoding Evasion Detection:** Identifies and decodes hidden payloads (such as malicious Base64 strings) designed to bypass basic text filters.
  * **Semantic Evasion Blocking:** Intercepts indirect manipulation tactics, including hypothetical scenarios and fictional world bypass prompts.

### 3. Output Exfiltration Prevention Guard (`Output Shield`)
* **Purpose:** Secures the final boundary before AI-generated responses reach the end-user.
* **Key Mechanisms:**
  * **Real-time Leak Scanning:** Automatically scans generated text for accidental or malicious exposure of sensitive enterprise assets (e.g., API keys, AWS credentials, credit card numbers, and internal secrets).
  * **Withholding Mechanism:** Instantly blocks leaking responses to protect company data and reputation.

---

## ⚙️ Core Engineering Principles

* **Low-Latency Execution:** Built to process checks within milliseconds, ensuring seamless user experience without noticeable lag.
* **Fail-Closed Principle:** If any internal exception, tool failure, or unexpected error occurs within the guardrail pipeline, the system **automatically blocks** the request/response by default, prioritizing absolute safety over availability.
* **Modular Design:** Easily extensible pipeline architecture allowing seamless integration of new security layers.

* # LLM Security Gateway & Multi-Layer Defense Orchestrator

A production-grade, centralized security gateway and reverse proxy middleware designed to orchestrate end-to-end defense-in-depth inspection pipelines for enterprise Large Language Model (LLM) architectures.

---

## 🛡️ Architecture & Threat Engineering

In enterprise deployments, scattering security checks across disparate files or unmanaged API wrappers creates severe security blind spots and compliance risks. 

This repository implements a **Centralized Security Gateway** that acts as an intelligent neural and lexical proxy. Every incoming request is intercepted and forced through a sequential, decoupled middleware pipeline enforcing strict **Fail-Closed** principles before reaching the core model inference endpoint.

---

### Core Security Layers & Pipeline

1. **Input Sanitization Layer (`InputSanitizationMiddleware`):** Intercepts payloads to strip prompt injection markers, system override commands, and unauthorized control tokens.
2. **Model Alignment Layer (`ModelAlignmentMiddleware`):** Evaluates deep semantic intent and guards against advanced adversarial jailbreaks, malware generation, and structural evasion.
3. **Fail-Closed Enforcement Engine:** Instantly halts pipeline execution and returns safe defaults upon encountering system exceptions or security violations.

---

## ⚙️ Software Engineering Principles


# AI Security SIEM & Real-Time Monitoring Dashboard 

An enterprise-grade Security Information and Event Management (SIEM) telemetry aggregator and real-time security operations center (SOC) dashboard designed for centralized AI infrastructure monitoring.

---

## 🛡️ Architecture & Threat Engineering

As organizations scale their Large Language Model (LLM) deployments across multiple microservices and gateways, decentralized security logs create profound operational blindness. 

This repository implements a **Centralized SIEM Telemetry Engine** that ingests real-time events from edge security gateways, aggregates critical threat metrics, runs automated anomaly detection algorithms, and exposes executive-ready Security Operations Center (SOC) dashboards.

---

### Core Components & Pipeline

1. **Telemetry Event Schema (`TelemetryEvent`):** Standardized data container capturing high-precision execution timestamps, source defense layers, request statuses, latencies, and threat categories.
2. **SIEM Ingestion & Analytics Engine (`SecuritySIEMProcessor`):** Acts as a centralized data lake handler, ingesting event streams and maintaining real-time counters.
3. **Automated Anomaly Detection:** Dynamically inspects ingestion windows for sudden threat velocity spikes or infrastructural pipeline errors.
4. **Executive Dashboard Generator:** Computes critical Key Performance Indicators (KPIs) such as total request volume, block rates, average latency profiles, and active security warnings.

---

## ⚙️ Software Engineering Principles

* **Stream-Processing Architecture:** Built for high-throughput, low-latency log ingestion and aggregation.
* **Separation of Concerns:** Decouples telemetry collection and anomaly detection logic from core gateway execution, ensuring minimal performance overhead.
* **Executive-Ready Telemetry:** Translates complex technical security events into clear, actionable business metrics for CISOs and compliance auditors.

---


* **Middleware Chain-of-Responsibility:** Decoupled inspection layers allow security administrators to inject, reorder, or remove validation steps without altering core gateway logic.
* **Open-Closed Principle (OCP):** New security checks can be implemented seamlessly by extending `SecurityPipelineMiddleware`.
* **Telemetry & Observability:** Every request captures precise latency profiling (ms) and sequential layer telemetry for enterprise SIEM ingestion and auditing.





# Indirect Prompt Injection (IPI) Defense Shield

An advanced security module designed to neutralize Indirect Prompt Injection (IPI) attacks by enforcing strict structural context isolation, boundary sandboxing, and control token neutralization for untrusted external data sources.

---

## 🛡️ Architecture & Threat Engineering

When enterprise AI agents process external data sources—such as web scrapers, ingested RAG documents, or external emails—adversaries can embed hidden malicious instructions. Because conventional LLMs struggle to distinguish between **trusted system instructions** and **untrusted data**, the model blindly executes these injected commands.

This repository implements a **Semantic Sandboxing & Dual-Context Isolation Proxy** that intercepts external data before it reaches the core LLM inference engine, rendering malicious control sequences completely inert.

---

### Core Defensive Mechanisms

1. **Control Token Neutralization:** Scans incoming payloads for known jailbreak, breakout, and system override patterns (`ignore previous instructions`, `system override`, etc.) and safely neutralizes them in transit.
2. **Structural Sandboxing:** Wraps all external, untrusted content inside strict XML boundaries (`<untrusted_external_data>`) accompanied by explicit machine-readable guardrail comments instructing the LLM to treat the block purely as passive data.
3. **Telemetry & Threat Logging:** Captures precise warning logs and threat categorizations for centralized enterprise SIEM ingestion.

---

## ⚙️ Software Engineering Principles

* **Separation of Concerns:** Decouples data ingestion pipelines from core prompt execution logic.
* **Fail-Safe Data Sanitization:** Guarantees that untrusted external context is structurally disarmed prior to prompt assembly.
* **Extensible Regular Expression Engine:** Easily adjustable pattern lists to catch evolving prompt injection signatures.

---


# Inference-Time Guardrails & Chain-of-Thought Auditing Shield
An advanced security module designed to neutralize Inference-Time Reasoning and Chain-of-Thought (CoT) Exploitation by enforcing real-time inspection, token auditing, and semantic guardrail alignment on hidden internal scratchpads of deep reasoning models.

## 🛡️ Architecture & Threat Engineering
When enterprise AI agents utilize deep reasoning models (such as o1/o3 architectures) that perform extensive internal "thinking" steps before producing a final response, sophisticated adversaries can execute Reasoning Loop Poisoning. By injecting philosophical, hypothetical, or contradictory narratives into the prompt, attackers trick the model's internal scratchpad into self-justifying security policy bypasses under false pretexts (e.g., emergency debugging or educational testing).

This repository implements a Real-Time Inference Guardrail Proxy that intercepts internal reasoning tokens on-the-fly, instantly halting malicious reasoning loops before sensitive outputs or compromised logic can reach the final response layer.

# Core Defensive Mechanisms
Real-Time Scratchpad Inspection: Continuously scans internal generation streams (Hidden Scratchpads) for unauthorized justification patterns and policy bypass narratives.

Reasoning Loop Interception: Instantly cuts off and halts generation when a manipulation or subversion attempt is detected within the model's thought process.

Guardrail Alignment & Telemetry: Logs precise reasoning audit trails for enterprise security monitoring and centralized SIEM ingestion.

# ⚙️ Software Engineering Principles
Low-Latency Runtime Auditing: Designed to inspect token streams dynamically during inference without introducing disruptive overhead.

Fail-Safe Interception: Automatically overrides compromised thought paths with secure fallback messages.

Extensible Pattern Matching: Easily configurable regular expression engine to detect evolving chain-of-thought jailbreak signatures.
