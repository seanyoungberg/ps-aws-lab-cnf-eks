# AWS infrastructure
clone the repo
```
git clone https://spring.paloaltonetworks.com/rweglarz/cnv3
```

goto terraform folder
```
cd cnv3/tf
```

download lambda function
```
curl -L -k https://github.com/aws-samples/eks-install-guide-for-multus/raw/main/cfn/templates/nodegroup/lambda_function.zip -O
```

create your value file: ../eks.tfvars, replace user with your user. Also if needed create/add your own **safe_ips**
```
cluster_name = "user-cn3" 
vpc_name  = "user-cn3-n1"
kubeconfig_output_path = "/Users/user/.kube/config-eks"
region = "eu-central-1"
key_pair = "user"
owner = "user"
```

init, plan and apply
```
terraform init
terraform plan --var-file=../eks.tfvars
terraform apply
```
Note that the kubeconfig file above is not the default, make sure that from now on that's the cluster you will use. For example export KUBECONFIG variable

# setup multus and scale the cluster
download and apply multus
```
curl -L -k kubectl apply -f https://raw.githubusercontent.com/aws/amazon-vpc-cni-k8s/master/config/multus/v3.7.2-eksbuild.1/aws-k8s-multus.yaml -O
kubectl apply -f aws-k8s-multus.yaml
```
Autoscaling group will have 0 nodes now. Scale it up. Adjust the region and name as needed
```
aws autoscaling set-desired-capacity --region eu-central-1 --auto-scaling-group-name rwe-cnv3-ng1 --desired-capacity 2
```

# Helm
go to the main folder when you cloned the repo

create the helm values file: eks-h.yaml, something like:
```
---
common:
  cr: "gcr.io/gcp-gcs-tse/cn-series"
  versionPanos: "10.2.0-c367"
  versionInit: "3.0.0-b3"
  versionCni: "3.0.0d_10_a26df862ed"
  pullSecretName: gcr-json-key

panorama:
  authKey: "xyz"
  ip: "my-panorama"
  dg: dg_k8s_cnv3
  ts: ts_k8s_cnv3

dp:
  dpdk: false
  cpu: 1
  networks:
  - name: ha2
    pciBusID: "0000:00:06.0"
    ip:
      fw0: "172.18.3.101/32"
      fw1: "172.18.3.102/32"
  - name: net1
    pciBusID: "0000:00:07.0"
  - name: net2
    pciBusID: "0000:00:08.0"
```

apply crds
```
kubectl apply -f cnv3/crds/pan-cn-mgmt-slot-crd.yaml
kubectl apply -f cnv3/crds/plugin-serviceaccount.yaml
```

create pull secret for gcr registry, you need the sa json file file 
```
kubectl -n kube-system create secret docker-registry gcr-json-key \
                --docker-server=gcr.io \
                --docker-username=_json_key \
                --docker-password="$(cat gcp-gcs-tse-openshiftsvc-a2c14ef0f49f.json)" \
                --docker-email=doesnotexist@doesnotexist.com.or.eu
```

install replace **mycn** with something else if you so desire
```
helm install mycn cnv3 --values eks-h.yaml 
```
