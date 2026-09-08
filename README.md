# DESIGN AND EVALUATION OF A LIGHTWEIGHT MUTUAL AUTHENTICATION AND ENCRYPTION FRAMEWORK FOR RESOURCE-CONSTRAINED IOT DEVICES

## Research Proposal Repository

### Course
IDB30102 Research Methodology (BCS)

### Group Number
AG

---

## Group Members

| No. | Student Name | Student ID |
|---|---|---|
| 1 | SHAKIRUL IRFAN BIN SAZALI AFFANDI | 52215125804 |
| 2 | MUHAMMAD SHAUQI HAKIMI BIN SALLEUDIN | 52215125221 |
| 3 | OMAR ASRAF BIN KADER MOHIDEEN | 52215125977 |
| 4 | MUHAMMAD ADAM FARHAN BIN ZAINUDDIN | 52215125455 |

---

## 1. Research Area

This research is about **IoT security**, especially device authentication and encryption.

The research focuses on IoT devices that have limited resources such as processing power, memory and energy.

The main purpose is to find a security method that can protect IoT devices without using too many resources.

---

## 2. Research Problem

IoT devices are used in many places such as smart homes, smart campuses and sensor networks.

However, many IoT devices have limited processing power, memory and energy. This can make it difficult to use security methods that need a lot of resources.

IoT devices can also face different security problems such as:

- Impersonation attacks
- Replay attacks
- Message tampering
- Unauthorized access
- Information leakage

Authentication can help to check whether a device is trusted or not. Encryption can protect the data sent between devices.

However, adding security can also increase processing time, communication cost and memory usage.

From the previous literature review, different studies use different methods, datasets, hardware and testing environments. Some studies also mainly use simulation or small test environments.

Because of this, it can be difficult to compare the results of different studies.

Therefore, this research will design and evaluate a lightweight security framework for resource-constrained IoT devices.

---

## 3. Research Aim

The aim of this research is to **design and evaluate a lightweight mutual authentication and encryption framework for resource-constrained IoT devices**.

The framework is designed to protect IoT communication while keeping the resource usage at an acceptable level.

---

## 4. Research Objectives

This research has three objectives:

### RO1
To study existing IoT device authentication and lightweight encryption techniques for resource-constrained IoT devices.

### RO2
To design and implement a lightweight mutual authentication and encryption framework for communication between IoT devices and a gateway.

### RO3
To evaluate the proposed framework based on security and performance and compare it with a basic system without authentication and encryption.

---

## 5. Proposed Solution

The proposed solution is a lightweight security framework for IoT devices.

The framework will allow an IoT device and a gateway to check each other's identity before communication.

The framework will include:

- Device registration
- Identity checking
- Mutual authentication
- Challenge and response
- HMAC verification
- Nonce or timestamp checking
- Session key establishment
- Encryption
- Message integrity checking
- Replay protection
- Security logging

A basic prototype is planned using **Python** in a controlled local environment.

Sample IoT data such as temperature, humidity, device status, device ID and timestamp will be used for testing.

---

## 6. Research Methodology

This research will use an **Experimental Research Methodology**.

This method is suitable because the proposed framework will be developed and tested.

The testing will include normal communication and selected attacks.

The main testing areas are:

1. Normal communication
2. Impersonation attack
3. Replay attack
4. Message tampering

The results will then be compared with a basic system without the proposed security framework.

### Development Process

The development process will include:

1. Identify the requirements
2. Design the framework
3. Develop the prototype
4. Test the prototype
5. Evaluate the results

---

## 7. Proposed Evaluation Plan

### 7.1 Baseline

The proposed framework will be compared with a basic communication setup without authentication and encryption.

This comparison will show the effect of adding the security framework.

### 7.2 Test Environment

The testing will be done in a controlled local environment.

The preliminary prototype will use Python.

Sample IoT data will include:

- Device ID
- Temperature
- Humidity
- Device status
- Timestamp
- Sample messages

No private or confidential data will be used.

### 7.3 Security Testing

The framework will be tested against:

- Impersonation
- Replay
- Message tampering

The tests will check whether the framework can identify and reject invalid or modified communication.

### 7.4 Performance Metrics

The following measurements will be used:

- Authentication time
- Processing time
- Communication delay
- Message overhead
- Memory usage
- Computational cost

### 7.5 Security Metrics

The security evaluation will look at:

- Authentication success
- Impersonation detection
- Replay detection
- Tampering detection
- Message integrity
- Data protection

---

## 8. Proposed System Architecture

The proposed system will have IoT devices and a gateway.

```text
+-------------------+
|    IoT Device 1   |
+-------------------+
          |
          | Authentication
          | and Encryption
          |
          v
+-------------------+
|      Gateway      |
+-------------------+
          |
          | Authentication
          | and Encryption
          |
          v
+-------------------+
|    IoT Device 2   |
+-------------------+
