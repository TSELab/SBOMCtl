init:
	bash ./bootstrap.sh
	@echo "run source virtualenv/bin/activate to run the other targets"

test:
	py.test tests

server:
	bash runserver.sh

.PHONY: init test
