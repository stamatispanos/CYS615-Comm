#! /bin/bash

# flush the tables
iptables -F
iptables -Z

# drop everything by Default
iptables -P INPUT DROP



