# ai_detect.py
import sys
from nudenet import NudeClassifier
import os

classifier = NudeClassifier()
filepath = sys.argv[1]
result = classifier.classify(filepath)
safe_prob = result[filepath]['safe']
unsafe_prob = result[filepath]['unsafe']
os.remove(filepath)

# Tweak this threshold as you wish
if unsafe_prob > 0.9:
    print("unsafe")
else:
    print("safe")
