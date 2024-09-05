#!/bin/bash

ansible-galaxy collection build -f
ansible-galaxy collection install hasnimehdi91-greenbone_gvm-1.0.0.tar.gz -f