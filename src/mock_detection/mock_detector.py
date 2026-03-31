import time
import random

class MockDetector():
    """
    Placeholder module for testing / demo
    """


    def simulate_attack(self, t, severity) -> int:
        # Sleeps t then returns detection value
        time.sleep(t)
        return severity
    
    def simulate_detection(t) -> int:
        # sleeps t then returns random int 0 - 100
        time.sleep(t)
        return random.randint(0, 100)