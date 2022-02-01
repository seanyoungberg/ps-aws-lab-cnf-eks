# Intro
The lab demo is meant to show / help with sample setup, not necessarily the most correct one when it comes to the way BGP is configured or routes are propagated

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
\! NOTE: the kubeconfig file above is not the default, make sure that from now on that's the cluster you will use. For example export KUBECONFIG variable

# jump host preparation
copy the the kernel module binaries to jump host, replace the name accordingly
```
scp bin/igb_uio.ko bin/rte_kni.ko  aws-cnv3-jump:
```
ssh to jump host and move the files to nginx web folder
```
ssh aws-cnv3-jump -c sudo mv igb_uio.ko rte_kni.ko /var/www/html/
```
\! NOTE: that these modules are specific to the ami used for the nodes, hence if you use a different ami you will most likely need to recompile the modules

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

# panorama
Create device group and template stack that will be referenced later on. To bring up BGP peering with multus hosts deployed by TF you will need to create a template with the necessary VR/BGP/interface configuration. The cli commands creating these are in the *panorama_bgp_template.cli* file. Reference that template in the template stack.

# Helm
go to the main folder when you cloned the repo

create the helm values file: eks-h.yaml, something like:
```
---
common:
  cr: "gcr.io/gcp-gcs-tse/cn-series"
  versionPanos: "10.2.0-c395"
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
      fw0: "172.16.3.101/32"
      fw1: "172.16.3.102/32"
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

# secondary IPs and routes
you can create an alias or a convenient function in your shell environment like so:
```
function awsinstancebyip  { aws ec2 describe-instances --region eu-central-1 --filter Name=private-ip-address,Values=$1 | jq '.Reservations[0].Instances[0] | {"id":.InstanceId, "ni": .NetworkInterfaces | [.[] | {"di":.Attachment.DeviceIndex,"ip":.PrivateIpAddress,"eni":.NetworkInterfaceId} ] | sort_by(.di)}'; }
```
Find the K8S hosting the DP pods

## secondary IPs for HA
IP addresses on the ha2 link 172.16.3.101 and 172.16.3.102 are assigned to K8S nodes hosting the dp-0 and dp-1 accordingly (in this .172 and .247)
```
aws ec2 assign-private-ip-addresses --region eu-central-1 --allow-reassignment \
    --private-ip-addresses 172.16.3.101 \
    --network-interface-id $(awsinstbyip 172.16.1.172 | jq -r '.ni[1].eni')

aws ec2 assign-private-ip-addresses --region eu-central-1  --allow-reassignment \
    --private-ip-addresses 172.16.3.102 \
    --network-interface-id $(awsinstbyip 172.16.1.247 | jq -r '.ni[1].eni')
```

## secondary IPs for traffic
Find the K8S node hosting the active DP pod, we will put it into *nip* variable to avoid putting it into too many places
```
nip=172.16.1.247
aws ec2 assign-private-ip-addresses --region eu-central-1  --allow-reassignment \
    --private-ip-addresses 172.16.4.199 \
    --network-interface-id $(awsinstbyip $nip | jq -r '.ni[2].eni')
aws ec2 assign-private-ip-addresses --region eu-central-1  --allow-reassignment \
    --private-ip-addresses 172.16.5.199 \
    --network-interface-id $(awsinstbyip $nip | jq -r '.ni[3].eni')
```

## routes for traffic
Find the routing table associated with the multus subnets and add the routes. Note we're using *nip* variable from the previous step
```
rt=rtb-0cd9f78f4a1a0b02b
aws  ec2 create-route   --region eu-central-1 --destination-cidr-block 172.17.4.0/24 \
    --route-table-id $rt \
    --network-interface-id $(awsinstbyip $nip | jq -r '.ni[3].eni')
aws  ec2 create-route   --region eu-central-1 --destination-cidr-block 172.17.5.0/24 \
    --route-table-id $rt \
    --network-interface-id $(awsinstbyip $nip | jq -r '.ni[2].eni')
```

# extras
## bug in 10.2.0-c367
\! NOTE: this should not be needed, as of panos c395
in the panos 10.2.0-c367 there is a [bug PAN-187106](https://jira-hq.paloaltonetworks.local/browse/PAN-187106) which results in failed panorama pushed commit. To workaround it exec into both mps
```
kubectl exec -it cnv3fw1-sts-0-0 -- bash
kubectl exec -it cnv3fw1-sts-1-0 -- bash
```
and run
```
telemcfg_gen
```
repush

