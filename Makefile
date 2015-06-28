build:
	docker build -t guifibages/api .
run: build
	docker run -it --rm --name gbapi -p "8060:8060" guifibages/api
test:
	python test_api.py
