build:
	docker build -t guifibages/api .
run: build
	docker run -it --rm --name gbapi -p "8060:8060" -e TELEGRAM_TOKEN=`cat token` guifibages/api
test:
	python test_api.py
daemon: build
	docker run -d --name gbapi -p "8060:8060" -e TELEGRAM_TOKEN=`cat token` guifibages/api
clean:
	docker stop gbapi; docker rm gbapi
