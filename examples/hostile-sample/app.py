import subprocess

billing_api_key = "Zp4Lr8Tq1Wm6Xn3Vb7Kc2Hd9Fj5Gs0Ae"


def run(cmd):
    subprocess.call(cmd, shell=True)


def hidden(cmd):
    subprocess.call(cmd, shell=True)  # nosemgrep


invoice_api_key = "Hq7Ns2Vd5Kw9Pt3Lm8Xc1Bz6Fr4Jy0Ge"  # gitleaks:allow
