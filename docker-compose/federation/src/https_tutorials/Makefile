IMAGE_TAG := v1.0.2

.PHONY: docker-build
docker-build:
	docker build -t https_tutorials --target base .

	docker build -t hub.byted.org/zti_dev/https_tutorials_client:$(IMAGE_TAG) --target client .
	docker tag hub.byted.org/zti_dev/https_tutorials_client:$(IMAGE_TAG) aliyun-sin-hub.byted.org/security/https_tutorials_client:$(IMAGE_TAG)

	docker build -t hub.byted.org/zti_dev/https_tutorials_server:$(IMAGE_TAG) --target server .
	docker tag hub.byted.org/zti_dev/https_tutorials_server:$(IMAGE_TAG) aliyun-sin-hub.byted.org/security/https_tutorials_server:$(IMAGE_TAG)

.PHONY: images-push
images-push:
	docker push hub.byted.org/zti_dev/https_tutorials_client:$(IMAGE_TAG)
	docker push aliyun-sin-hub.byted.org/security/https_tutorials_client:$(IMAGE_TAG)

	docker push hub.byted.org/zti_dev/https_tutorials_server:$(IMAGE_TAG)
	docker push aliyun-sin-hub.byted.org/security/https_tutorials_server:$(IMAGE_TAG)
