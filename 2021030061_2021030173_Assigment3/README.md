# TucSec Malware Detection Project

## Overview

This project is designed to detect and quarantine malware files based on their signatures. It includes three main tasks:

1. **Task A**: Signature Database Creation and Malware Detection
2. **Task B**: Search and Quarantine
3. **Task C**: Real-time Malware Monitoring

## Prerequisites

- Python 3.x
- Required Python packages (can be installed via `pip`):
    - `argparse`
    - `hashlib`
    - `os`
    - `random`
    - `shutil`
    - `string`
    - `datetime`
    - `logging`
    - `watchdog`

## Usage

### Task A: Signature Database Creation and Malware Detection

1. **Create Signature Database**:
     ```sh
     make create_database
     ```

2. **Create Test Files**:
     ```sh
     make create_test_files
     ```

3. **Detect Malware**:
     ```sh
     make detect_malware
     ```

4. **Show PDF Hashes**:
     ```sh
     make show_pdf_hashes
     ```

5. **Run All Task A Functions**:
     ```sh
     make taskA
     ```

### Task B: Search and Quarantine

1. **Search and Quarantine Malware**:
     ```sh
     make taskB
     ```

### Task C: Real-time Malware Monitoring

1. **Monitor Directory for Malware in Real-time**:
     ```sh
     make taskC
     ```

### Clean Up

1. **Clean Generated Files and Logs**:
     ```sh
     make clean
     ```

## Directory Structure

- `taskA.py`: Contains functions for signature database creation and malware detection.
- `taskB.py`: Contains functions for searching and quarantining malware.
- `taskC.py`: Contains functions for real-time malware monitoring.
- `Makefile`: Contains make targets for running various tasks.
- `files/`: Directory containing test files, sample PDFs, and quarantine directory.
- `malware_signatures.txt`: File containing malware signatures.
- `detection_report.log`: Log file for malware detection reports.

## Notes

- Ensure that the `files/` directory and its subdirectories exist before running the tasks.
- The `malware_signatures.txt` file should be generated using the `create_database` task before running other tasks.
- The `detection_report.log` file will contain logs of detected malware and quarantined files.

## License

This project is licensed under the MIT License.