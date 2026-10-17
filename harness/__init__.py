"""Harness: measure whether AI-generated security patches fix real CVEs without
breaking tests.

Pipeline: setup_case -> patch -> verify -> report. Cases come from CVE-Bench
(see benchmarks/cves.yaml).
"""
