---
title: Automatic Attack Incident Proof-of-concept Generator
date: 2024-12-09 08:58:21
tags: Research
---

There were numerous attack incidents in 2021 and 2022, resulting in significant losses. Upon closer examination, some of these exploits revealed a substantial time delay between the attack transaction and its detection by protocol members. Here are a few notable examples:

With rapid development in protocol security, secure development practices have been introduced. Before deployment, protocols undergo security reviews (audits). After deployment, bug bounty programs are implemented, and monitoring systems are established to ensure quick responses to exploits. Organizations like SEAL911 and other security-focused communities have emerged to provide real-time assistance, significantly reducing the time between an attack and its detection.

However, identifying the root cause and analyzing from exploits still takes time, especially as attack incidents become increasingly complex. Attack transactions are often intricate, making analysis challenging. While smart contract vulnerabilities like arbitrary calls or access control issues are relatively easier to detect, DeFi-specific security issues, such as exchange rate manipulation, precision loss, or oracle manipulation, require a more in-depth examination of transaction details.

Developing proof-of-concepts (PoCs) for exploits is crucial for identifying root causes and assisting protocol teams in implementing timely mitigation measures. However, the process can be tedious and time-consuming. Based on my experience contributing to DeFiHackLabs, the largest Web3 security community known for its extensive collection of PoCs, I have observed similarities between creating PoCs and analyzing transaction invocation flows using certain transaction analysis tools.