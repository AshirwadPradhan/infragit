ifeq ($(OS),Windows_NT)
ROOT_D := $(shell cd)
systest:
	@echo Windows
clean:
	rmdir /s /q $(ROOT_D)\src\dbctest
	rmdir /s /q $(ROOT_D)\src\dbs
	rmdir /s /q $(ROOT_D)\src\dbtest
	rmdir /s /q $(ROOT_D)\src\__pycache__
init:
	mkdir $(ROOT_D)\src\dbctest
	mkdir $(ROOT_D)\src\dbtest
	mkdir $(ROOT_D)\src\dbs
	echo {} > $(ROOT_D)\src\dbs\logclient.json
	echo {} > $(ROOT_D)\src\dbs\repoinf.json
	echo {} > $(ROOT_D)\src\dbs\users.json
run-server:
	@echo Server is NOT supported in Windows... Use a Linux Machine!
run-client:
	python $(ROOT_D)\src\client.py
else
ROOT_L := $(shell pwd)
systest:
	@echo Linux
clean:
	rm -rf $(ROOT_L)/src/dbctest
	rm -rf $(ROOT_L)/src/dbs
	rm -rf $(ROOT_L)/src/dbtest
	rm -rf $(ROOT_L)/src/__pycache__
init:
	mkdir $(ROOT_L)/src/dbctest
	mkdir $(ROOT_L)/src/dbs
	echo {} > $(ROOT_L)/src/dbs/logclient.json
	echo {} > $(ROOT_L)/src/dbs/repoinf.json
	echo {} > $(ROOT_L)/src/dbs/users.json
	mkdir $(ROOT_L)/src/dbtest
run-server:
	uwsgi --master --https localhost:5683,src/server-public-key.pem,src/server-private-key.pem --wsgi-file src/gateway.py --callable app --processes 4 --threads 4
run-client:
	python3 $(ROOT_L)/src/client.py
endif