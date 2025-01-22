An Intrusion Detection System (IDS) is like a security camera for your network. Just as security cameras help identify suspicious activities in the physical world, 
an IDS will monitor your network to help detect any potential cyber attacks and security breaches.

Table of Contents
Understanding the Types of IDS

How to Setup Your Development Environment

Building the Core IDS Components

Building the Packet Capture Engine

Building the Traffic Analysis Module

Building the Detection Engine

Building the Alert System

Putting It All Together

Ideas to Extend the IDS

Security Considerations

Testing the IDS on Mock Data

-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Understanding the Types of IDS
Before we jump into the coding part, let’s understand the types of IDS:

Network-based IDS (NIDS): This system monitors network traffic for suspicious activity.

Host-based IDS (HIDS): This system monitors system logs and file changes on individual hosts and is not directly deployed in the network.

Signature-based IDS: This system is either in the network or on the host and identifies attack patterns based on known patterns.

Anomaly-based IDS: This system identifies unusual behavior using heuristics and prediction algorithms that are trained on previously seen attack patterns.


-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

uilding the Core IDS Components
Our IDS will comprise of four main components:

A packet capture system

Traffic analysis module

A detection engine

An alert system

Building the Packet Capture Engine
Let’s start with the packet capture engine. We’ll use Scapy for this. Scapy is a networking library that allows us to perform network and network-related operations using Python.


code:-

from scapy.all import sniff, IP, TCP
from collections import defaultdict
import threading
import queue

class PacketCapture:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.stop_capture = threading.Event()

    def packet_callback(self, packet):
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)

    def start_capture(self, interface="eth0"):
        def capture_thread():
            sniff(iface=interface,
                  prn=self.packet_callback,
                  store=0,
                  stop_filter=lambda _: self.stop_capture.is_set())

        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()

    def stop(self):
        self.stop_capture.set()
        self.capture_thread.join()

        
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Let’s quickly walk through the code and understand what these functions do. For this, you will be using threading and queues to efficiently process and capture network packets.

The init method initializes the class by creating a queue.Queue to store captured packets and a threading Event to control when the packet capture should stop. The packet_callback method acts as a handler for each captured packet and checks if the packet contains both IP and TCP layers. If so, it adds it to the queue for further processing.

The start_capture method begins capturing packets on a specified interface (defaulting to eth0 to capture packets from the Ethernet interface). Run ifconfig to understand the available interfaces and select the appropriate interface from the list.

The function spawns a separate thread to run Scapy’s sniff function, which continuously monitors the interface for packets. The stop_filter parameter ensures the capture stops when the stop_capture event is triggered.

The stop method stops the capture by setting the stop_capture event and waits for the thread to finish execution, ensuring the process terminates cleanly. This design allows for seamless real-time packet capturing without blocking the main thread.

Building the Traffic Analysis Module
Now, let’s write the traffic analysis module. This module will process captured packets and extract relevant features.

code:-

class TrafficAnalyzer:
    def __init__(self):
        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None
        })

    def analyze_packet(self, packet):
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

            flow_key = (ip_src, ip_dst, port_src, port_dst)

            # Update flow statistics
            stats = self.flow_stats[flow_key]
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            current_time = packet.time

            if not stats['start_time']:
                stats['start_time'] = current_time
            stats['last_time'] = current_time

            return self.extract_features(packet, stats)

    def extract_features(self, packet, stats):
        return {
            'packet_size': len(packet),
            'flow_duration': stats['last_time'] - stats['start_time'],
            'packet_rate': stats['packet_count'] / (stats['last_time'] - stats['start_time']),
            'byte_rate': stats['byte_count'] / (stats['last_time'] - stats['start_time']),
            'tcp_flags': packet[TCP].flags,
            'window_size': packet[TCP].window
        }

In this code section, we define the TrafficAnalyzer class to analyze network traffic. Here we track connection flows and calculate statistics for packets in real time. We use the defaultdict data structure in Python to manage connections and flow statistics by organizing data by unique flows.

The __init__ method initializes two attributes: connections, which stores lists of related packets for each flow, and flow_stats, which stores aggregated statistics for each flow, such as packet count, byte count, start time, and the time of the most recent packet.

The analyze_packet method processes each packet. If the packet contains IP and TCP layers, it extracts the source and destination IPs and ports, forming a unique flow_key to identify the flow. It updates the statistics for the flow by incrementing the packet 
count, adding the packet’s size to the byte count, 
and setting or updating the start and last time of the flow. Eventually, it calls extract_features to calculate and return additional metrics.

The extract_features method computes detailed characteristics of the flow and the current packet. These include the packet size, flow duration, packet rate, byte rate, TCP flags, and the TCP window size. These metrics are quite useful to identify patterns, anomalies, or potential threats in network traffic.
        
  -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
  Building the Detection Engine

  Now we will define our detection engine that will implement both the signature as well as the anomaly-based detection mechanisms:

from sklearn.ensemble import IsolationForest
import numpy as np

class DetectionEngine:
    def __init__(self):
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self.signature_rules = self.load_signature_rules()
        self.training_data = []

    def load_signature_rules(self):
        return {
            'syn_flood': {
                'condition': lambda features: (
                    features['tcp_flags'] == 2 and  # SYN flag
                    features['packet_rate'] > 100
                )
            },
            'port_scan': {
                'condition': lambda features: (
                    features['packet_size'] < 100 and
                    features['packet_rate'] > 50
                )
            }
        }

    def train_anomaly_detector(self, normal_traffic_data):
        self.anomaly_detector.fit(normal_traffic_data)

    def detect_threats(self, features):
        threats = []

        # Signature-based detection
        for rule_name, rule in self.signature_rules.items():
            if rule['condition'](features):
                threats.append({
                    'type': 'signature',
                    'rule': rule_name,
                    'confidence': 1.0
                })

        # Anomaly-based detection
        feature_vector = np.array([[
            features['packet_size'],
            features['packet_rate'],
            features['byte_rate']
        ]])

        anomaly_score = self.anomaly_detector.score_samples(feature_vector)[0]
        if anomaly_score < -0.5:  # Threshold for anomaly detection
            threats.append({
                'type': 'anomaly',
                'score': anomaly_score,
                'confidence': min(1.0, abs(anomaly_score))
            })

        return threats
This code defines a hybrid system that combines the signature-based and anomaly-based detection methods. 
We use the Isolation Forest model to detect anomalies and also use pre-defined rules for identifying specific
attack patterns. If you would like to know more about how the Isolation Forest model works, check out this article.

In this code snippet, the train_anomaly_detector method trains the Isolation Forest model using a dataset of
normal traffic features. This enables the model to differentiate typical traffic patterns from anomalies.

The detect_threats method evaluates network traffic features for potential threats using two approaches:

Signature-Based Detection: It iteratively goes through each of the predefined rules, applying the rule’s 
condition to the traffic features. If a rule matches, a signature-based threat is recorded with high confidence.

Anomaly-Based Detection: It processes the feature vector (packet size, packet rate, and byte rate) through the 
Isolation Forest model to calculate an anomaly score. If the score indicates unusual behavior, the detection engine
triggers it as an anomaly and produces a confidence score proportional to the anomaly’s severity.

Finally, we return the aggregated list of identified threats with their respective annotation (either signature or anomaly), 
the rule or score that triggered the anomaly, and a confidence score that suggests how likely it is that the identified pattern is a threat.


-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Building the Alert System
Now let’s build the last component of our IDS which is the alert system. It will process and log detected threats in a structured way. 
You will also have the option to extend the system to include additional notification mechanisms like Slack, Jira tickets, and so on

import logging
import json
from datetime import datetime

class AlertSystem:
    def __init__(self, log_file="ids_alerts.log"):
        self.logger = logging.getLogger("IDS_Alerts")
        self.logger.setLevel(logging.INFO)

        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def generate_alert(self, threat, packet_info):
        alert = {
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat['type'],
            'source_ip': packet_info.get('source_ip'),
            'destination_ip': packet_info.get('destination_ip'),
            'confidence': threat.get('confidence', 0.0),
            'details': threat
        }

        self.logger.warning(json.dumps(alert))

        if threat['confidence'] > 0.8:
            self.logger.critical(
                f"High confidence threat detected: {json.dumps(alert)}"
            )
            # Implement additional notification methods here
            # (e.g., email, Slack, SIEM integration)
            
The init method sets up a logger named IDS_Alerts with an INFO logging level to capture alert information. It writes logs to a specified file, ids_alerts.log by default.
A FileHandler directs logs to the file, while the Formatter ensures the logs follow a consistent format.

The generate_alert method is responsible for creating structured alert entries. Each alert includes 
key information such as the timestamp of detection, the type of threat, the source and destination 
IPs involved, the confidence level of the detection, and additional threat-specific details.
These alerts are logged as WARNING level messages in JSON format.

If the confidence level of a detected threat is high (greater than 0.8), the alert is escalated 
and logged as a CRITICAL level message. Note that this method is designed to be extensible, allowing for 
additional notification mechanisms, such as sending alerts via email or integrating with third-party systems like Slack or SIEM solutions.

-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Putting it All Together
Now let’s integrate all the components together into our fully functional IDS solution:

class IntrusionDetectionSystem:
    def __init__(self, interface="eth0"):
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine()
        self.alert_system = AlertSystem()

        self.interface = interface

    def start(self):
        print(f"Starting IDS on interface {self.interface}")
        self.packet_capture.start_capture(self.interface)

        while True:
            try:
                packet = self.packet_capture.packet_queue.get(timeout=1)
                features = self.traffic_analyzer.analyze_packet(packet)

                if features:
                    threats = self.detection_engine.detect_threats(features)

                    for threat in threats:
                        packet_info = {
                            'source_ip': packet[IP].src,
                            'destination_ip': packet[IP].dst,
                            'source_port': packet[TCP].sport,
                            'destination_port': packet[TCP].dport
                        }
                        self.alert_system.generate_alert(threat, packet_info)

            except queue.Empty:
                continue
            except KeyboardInterrupt:
                print("Stopping IDS...")
                self.packet_capture.stop()
                break

if __name__ == "__main__":
    ids = IntrusionDetectionSystem()
    ids.start()
In this code, the IntrusionDetectionSystem class sets up its core components: PacketCapture for capturing packets from a network interface,
TrafficAnalyzer for extracting and analyzing packet features, DetectionEngine for identifying threats using 
both signature-based and anomaly-based methods, and AlertSystem for logging and escalating detected threats. 
The interface parameter specifies the network interface to monitor, defaulting to eth0 (the generally named ethernet interface on most systems).

The start function initiates the IDS. It begins by starting packet capture on the specified interface and 
enters a loop to continuously process incoming packets. For each packet captured, the system extracts its 
features using the TrafficAnalyzer and analyzes them for potential threats using the DetectionEngine. 
If any threats are detected, the system generates detailed alerts through the AlertSystem.

The system runs in a loop until interrupted by either of the two key exceptions: queue.Empty, which occurs 
if no packets are available for processing, and KeyboardInterrupt, which stops the IDS gracefully by halting packet capture and exiting the loop.

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Testing the IDS on Mock Data
To validate the functionality of your IDS, you can test it using mock data that will simulate real-world network traffic. This will allow you to observe how the system processes packets, analyzes traffic, and generates alerts without requiring a live network environment.

Use the following function to test the IDS:

from scapy.all import IP, TCP

def test_ids():
    # Create test packets to simulate various scenarios
    test_packets = [
        # Normal traffic
        IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80, flags="A"),
        IP(src="192.168.1.3", dst="192.168.1.4") / TCP(sport=1235, dport=443, flags="P"),

        # SYN flood simulation
        IP(src="10.0.0.1", dst="192.168.1.2") / TCP(sport=5678, dport=80, flags="S"),
        IP(src="10.0.0.2", dst="192.168.1.2") / TCP(sport=5679, dport=80, flags="S"),
        IP(src="10.0.0.3", dst="192.168.1.2") / TCP(sport=5680, dport=80, flags="S"),

        # Port scan simulation
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=22, flags="S"),
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=23, flags="S"),
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=25, flags="S"),
    ]

    ids = IntrusionDetectionSystem()

    # Simulate packet processing and threat detection
    print("Starting IDS Test...")
    for i, packet in enumerate(test_packets, 1):
        print(f"\nProcessing packet {i}: {packet.summary()}")

        # Analyze the packet
        features = ids.traffic_analyzer.analyze_packet(packet)

        if features:
            # Detect threats based on features
            threats = ids.detection_engine.detect_threats(features)

            if threats:
                print(f"Detected threats: {threats}")
            else:
                print("No threats detected.")
        else:
            print("Packet does not contain IP/TCP layers or is ignored.")

    print("\nIDS Test Completed.")

if __name__ == "__main__":
    test_ids()
    
This will test the system against a variety of attacks like SYN flooding and port scanning.
