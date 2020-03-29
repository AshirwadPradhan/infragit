ifeq ($(OS),Windows_NT)
ROOT_D := $(shell cd)
systest:
	@echo Windows
clean:
	rmdir /s /q $(ROOT_D)\src\dbctest
	rmdir /s /q $(ROOT_D)\src\dbs
	rmdir /s /q $(ROOT_D)\src\dbtest
	rmdir /s /q $(ROOT_D)\src\__pycache__
	del /q $(ROOT_D)\src\*.pem
init:
	mkdir $(ROOT_D)\src\dbctest
	mkdir $(ROOT_D)\src\dbtest
	mkdir $(ROOT_D)\src\dbs
	echo {} > $(ROOT_D)\src\dbs\logclient.json
	echo {} > $(ROOT_D)\src\dbs\repoinf.json
	echo {} > $(ROOT_D)\src\dbs\users.json
install:
	pip install -r requirements.txt
run-server:
	@echo Server is NOT supported in Windows... Use a Linux Machine!
run-client:
	python $(ROOT_D)\src\client.py
ca-cert:
	python $(ROOT_D)\src\ca_cert_gen.py
server-cert:
	python $(ROOT_D)\src\server_cert_gen.py
	python $(ROOT_D)\src\csr_sign.py
cert: ca-cert server-cert
prepare-env: install init cert
else
ROOT_L := $(shell pwd)
UNAME_S := $(shell uname -s)
systest:
	@echo UNAME_S
clean:
	rm -rf $(ROOT_L)/src/dbctest
	rm -rf $(ROOT_L)/src/dbs
	rm -rf $(ROOT_L)/src/dbtest
	rm -rf $(ROOT_L)/src/__pycache__
	rm -rf $(ROOT_L)/src/*.pem
init:
	mkdir $(ROOT_L)/src/dbctest
	mkdir $(ROOT_L)/src/dbs
	echo {} > $(ROOT_L)/src/dbs/logclient.json
	echo {} > $(ROOT_L)/src/dbs/repoinf.json
	echo {} > $(ROOT_L)/src/dbs/users.json
	mkdir $(ROOT_L)/src/dbtest
install:
	pip3 install -r requirements.txt
ifeq ($(UNAME_S),Darwin)
	CFLAGS="-I/usr/local/opt/openssl/include"
	LDFLAGS="-L/usr/local/opt/openssl/lib"
	UWSGI_PROFILE_OVERRIDE=ssl=true
	pip3 install uwsgi --no-binary :all:
else
	pip3 install uwsgi
endif
run-server:
	uwsgi --master --https localhost:5683,src/server-public-key.pem,src/server-private-key.pem --wsgi-file src/gateway.py --callable app --processes 4 --threads 4
run-client:
	python3 $(ROOT_L)/src/client.py
ca-cert:
	python3 $(ROOT_L)/src/ca_cert_gen.py
server-cert:
	python3 $(ROOT_L)/src/server_cert_gen.py
	python3 $(ROOT_L)/src/csr_sign.py
cert: ca-cert server-cert
prepare-dev: install init cert
endif
