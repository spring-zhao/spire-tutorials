# https server
```
kubectl apply -f - << EOF
apiVersion: v1
kind: Namespace
metadata:
  name: tutorials
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: https-tutorials-server
  namespace: tutorials
spec:
  replicas: 1
  selector:
    matchLabels:
      app: monitor-tools
  template:
    metadata:
      labels:
        app: monitor-tools
    spec:
      containers:
      - name: https-tutorials-server
        # image: hub.byted.org/zti_dev/https_tutorials_server:v1.0.1
        image: aliyun-sin-hub.byted.org/security/https_tutorials_server:v1.0.1
        imagePullPolicy: Always
        volumeMounts:
          - name: spire-agent-socket
            mountPath: /run/spire/sockets/
      volumes:
        - name: spire-agent-socket
          hostPath:
            path: /run/spire/agent-sockets/
            type: DirectoryOrCreate
EOF
```
# https client
```
kubectl apply -f - << EOF
apiVersion: v1
kind: Namespace
metadata:
  name: tutorials
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: https-tutorials-client
  namespace: tutorials
spec:
  replicas: 1
  selector:
    matchLabels:
      app: monitor-tools
  template:
    metadata:
      labels:
        app: monitor-tools
    spec:
      containers:
      - name: https-tutorials-client
        # image: hub.byted.org/zti_dev/https_tutorials_client:v1.0.1
        image: aliyun-sin-hub.byted.org/security/https_tutorials_client:v1.0.1
        args:
        - "-ip"
        - "192.168.2.29"
        imagePullPolicy: Always
        volumeMounts:
          - name: spire-agent-socket
            mountPath: /run/spire/sockets/
      volumes:
        - name: spire-agent-socket
          hostPath:
            path: /run/spire/agent-sockets/
            type: DirectoryOrCreate
EOF
```