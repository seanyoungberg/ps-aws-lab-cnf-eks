# First steps
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

create your value file: eks.tfvars, replace user with your user
```
cluster_name = "user-cn3" 
vpc_name  = "user-cn3-n1"
kubeconfig_output_path = "/Users/user/.kube/config-eks"
region = "eu-central-1"
key_pair = "user"
owner = "user"
```

plan and apply
```
terraform plan --var-file=eks.tfvars
terraform apply
```
