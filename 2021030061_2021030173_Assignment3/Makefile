all:
	@echo "The all target is disabled."

create_database:
	python3 taskA.py --function create_database

create_test_files:
	python3 taskA.py --function create_test_files

detect_malware:
	python3 taskA.py --function detect_malware

show_pdf_hashes:
	python3 taskA.py --function show_pdf_hashes

taskA:
	python3 taskA.py --function create_database
	python3 taskA.py --function create_test_files
	python3 taskA.py --function detect_malware
	python3 taskA.py --function show_pdf_hashes

taskB:
	python3 taskB.py --function search_and_quarantine

taskC:
	python3 taskC.py -d files -s malware_signatures.txt -o detection_report.log

taskC_r:
	python3 taskC.py -d files -s malware_signatures.txt -o detection_report.log -r

clean:
	rm -rf malware_signatures.txt
	rm -rf files/test_files
	rm -rf files/quarantine
	rm -rf *.log