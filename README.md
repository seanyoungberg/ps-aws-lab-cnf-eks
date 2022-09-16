# Intro

The lab demo is meant to show / help with sample setup, not necessarily the most correct one when it comes to the way BGP is configured or routes are propagated

# Prerequisite
working:
* aws cli
* helm
* terraform
In the instructions the aws hosts are referred to by their name in the ssh_config configuration file, like below. This helps to reuse the commands later on when you rebuild the lab and IPs chagne etc
```
Host aws-cnv3-jump
  HostName 18.194.80.247
```


# Application Environment Overview

## Launch the lab environment

In this section, we will launch the lab environment. These are the steps that we will accomplish at this time.

- Start the lab on your designated Qwiklab account.
- Login to the AWS Console using the provided credentials and set up  IAM roles
- Subscribe to the Panorama appliance on the AWS Marketplace.
- Deploy EKS environment using Terraform

## Start Qwiklabs lab environment and login to AWS

1. Once you login to [paloaltonetworks.qwiklabs.com](https://paloaltonetworks.qwiklabs.com/), the Home page should display the Labs that you have access to. Identify and click on the Lab that says "_Professional Services - CN-Series Workshop_".

2. On the page that opens up, click on _Professional Services - CN-Series Workshop - EKS_.

3. On the Qwiklab environment, Click on _Start Lab_ Button to start the lab.

At this point, Qwiklabs will build an AWS account for you. In order to access the EC2 application instances via SSH in your environment, you will be using keys generated by Qwiklabs. There are two types of keys generated; PEM and PPK keys.

1. If you are on a MAC, you will be using ‘Terminal’ to connect to the devices via SSH. For this, click on the “Download PEM” link. This will download a file named “qwikLABS-L\*\*\*\*\*-\*\*\*\*\*.pem”.

   - Make sure to note the location where the file is downloaded. On a Mac, by default, it will be downloaded to “/Users/&lt;username>/Downloads”

2. If you are using a windows laptop to access this lab, you will need to have a ssh application like PuTTY installed. 
![](https://lh4.googleusercontent.com/KztKlSkNNaQU61dPFGIAxrgDK8OSeSy6SGbcfPaO4Yji-EzBR_leZ02KN3u9_Twcj1qVL5B0OYOD_hZt2z1YWT5NQI53PzHl4HOzJAGxMz5EdedRkG3z62p7aouOzV-bAyWY3cDPJBwdkLrrpw)

   - In this case, click on the “Download PPK” link. This will download a file named “qwikLABS-L\*\*\*\*\*-\*\*\*\*\*.ppk”.

![](https://lh4.googleusercontent.com/9mJrciMHAaP929OpmukkN2K7nJZAEWqHY9tiAOaAdJZPeMc7My1tTRJKj3ZNhbfKWbTcvY8gBjfkQ0Bhxlbxy3eptSvk_CeFIrdugaI8MYkyz_g_d6McJocu7mtDxymFRbvpoEgS9fqwya0Ipw)

6. To login to the AWS environment, right click on “Open Console’ and “Open link in Incognito window” for Chrome-based browsers. For other browsers, use the appropriate option to open the AWS Console in a new private tab.

![](https://lh6.googleusercontent.com/uT9aD3yPqEH281H3ArxEeD__pjYDaJMSyv6CN0Fe78cnAjkNa_TA5LMKqHw3hUNUkWGI-bO3YuxXSuehWHvbIPR-EL616pesbcCxdLDkoeYrApT3AuvRXXPazBH1TIIl4IUGUXGL0mO4faL2aSc)

7. On the AWS Console, copy over the IAM username and password from the previous tab.

![](https://lh5.googleusercontent.com/b9Wwy3UiNDKna9cJkaV0SvyP9YFhIJV9Q0t_mqzvjRlo_RUNXNlqxxhZ1gDOen_RTkMxQQSoLRG3QIXT7GqvnzbkgpxrqBASd8Be1ZSVas_o5DNtwfmcjnfhwwfysDITt2KHxhC6W33pZEiykg)![](https://lh4.googleusercontent.com/fpGosvriB6Z2pqvMM70L7xUCHEpmfj55-1_BaPR_pDIBxprGXVi_v_YZr1aY4kc1IFUIz7rRoELUhNFDUT51EHGSVw326zeDCBnhvd6DbpMlrvEgyIqWUMpCLY_SIbBtro2au3GYk8CetXrTlw)

8. Now, click on “Sign In”.

![](https://lh5.googleusercontent.com/J5se3uljpa6L3MK-TVqMxBBplVKQQnZ6Wrh5atg3h_RiYAZtJZgaqSAe4-uV5RCk7h3bQ-QrUSQMvOAKBDKjS6kQ4iILWerNNnnfkDN4ryx5WB1DxlyrpQyLCLhJfg_CjH98fwkre31l2hurVQ)

Once you are successfully logged in, you will land on the AWS Management Console.

![](https://lh6.googleusercontent.com/vLh-4_cDPwBtDGcH5Vq08ai8wCwVzRY_zNsCn8fxhKL493RamNO5PrZWNbxC8d54OXx1_FbVCb6z1uesMBE9kI7DW33NR31JHxIqAxCqR-_19vNYtX_uNtxasgVhDNIlfJPpVEozEwyzZcQSag)
**Figure:** The AWS Management Console

## Set up AWS Account permissions

The Qwiklab user account, by default, does not have the permissions to AWS Marketplace and CloudShell services, which are required for the purpose of this lab. We will now edit the permissions for the Qwiklab user account to provide access to those services.

On the AWS console,

9. If you see a message for ‘new AWS Console’ click on ‘Switch now’
10. On the search bar type ‘iam’.
11. Click on the link to _IAM_. A new IAM dashboard window will open.

![](https://lh6.googleusercontent.com/prkjUS9HYswz-jjKU1lmwO6vUu5NzB-ffyeWv0hpQcnmmWFpXWtPo0pSCn90Jig1xfa6paud-ITotC500osJpEiVR1FtRmhMa5RznNJOL1pd2rceW_eBCts2zRGBWmyzOANZJrPuSIMyKmr1MQ)

12. Click on ‘2’ below users.

![](https://lh3.googleusercontent.com/6i-i100jVqCcVvg9eA6QBzy6CBTU2Q0qGoc_4vjt7X7r7AlojhYW4h84aiTeWTym5UU6hLQBtKE0o9CPudc5RW6edyylGxMl4WNbupQQwVSZMXjRy83BxBUrZsVdS7FglsS6reBkdpL6Wqimcw)

13. Click on ‘awsstudent’.

![](https://lh3.googleusercontent.com/rCDrl8lHLPx-XWCqcAe5o1IA_-N1fVLHwod7pSxLc_wzPbWh2LP_m-Ipzi9Vc4RST-3NbqqBbIr6Q2_ggKLUsEPlTBt3jACeCiDvlNkj_xtakraRHo60hDInJpFoIz4Tv2qehfnnADUsThc3_g)

14. Expand the default policy by clicking on the small triangle icon against default_policy in the list.

![](https://lh5.googleusercontent.com/DoxiUC4CM9Mt8HH2oIBS1v6jf2mUnsQmIaiZoYbY6k8A0HjLVDm5rjVXWLOpZZ_c73jGpOVqq1jXINOT1ai8nR7H8ubd5EWkSTeaYRSmt1o9pOd7DxiQjCkM_JaF8B0g9JT2Rtz2SeavwIhJNA)

15. Click on the ‘Edit Policy’ button.

![](https://lh4.googleusercontent.com/VtZe2xx-WurO_LpxfiRcRPkPgZZrWv2x0TU-2MhhDEa1OmtoucFVhC9KoIRL-jLF7Re9SouK3LbRfkzJgyeJ9Y8FA93fuF30j13iR2cSvpDFJTxjc9q0aYkLFUFcpRO-rg5zJa7NMtwBp3OP_w)

16. Click the ‘JSON’ tab.

![](https://lh3.googleusercontent.com/o44YVIRRJZkh4Q27BgCtAclylZRMrlXKvRlVoZ6JmQoSaWvTV_L6gMMUEB038lVRobt-M5xiir8OVr6jW3tCH-KW85hb0LEdnOMNv-XQbR-VniOhV8_Mh91ZBfCfI5f8Sff0ys0uP1YyCDL0ww)

17. Scroll down to the Deny policy and remove two lines (**line number 27** and **line number 36**) listed below

```
"aws-marketplace:\*ubscribe",
...
"cloudshell:\*",
```

Make sure to delete the whole line.

![](https://lh6.googleusercontent.com/gYkT0FH78QpnP24zVZPpKgSdtDLf1qaqmMb0AIpHtJ_O1B1AtirKcG28AQ_GXedKM_eFjgN7-o_2ZEeRD7syK2fdYPN_X3OVvECY9y6FbLp75EsN3lVTGBM7ptpPZCLwvoYRupOOyoaTM9wNcg)

18. Click on ‘Review policy’ at the bottom of the screen.
19. On the next screen, click on ‘Save changes’.

![](https://lh6.googleusercontent.com/iZlrM6e0CPx6Wv6ylxAU9R1wUnpAjlEj697Nu6VOd-sCOqUwhERAOB_JMCDXiRHJn_4XIQvtV-OV07Q1G98dUnS45DcxJfmwdEM5c6vF4Illor73BBw9p7_6SEqFRQ_OFH5Ky9nbeBWKk-vobQ)

20. Account setup is now complete.


## Subscribe to Panorama on the AWS Marketplace

In this section, we will deploy the AWS Cloud resources required for the purpose of this lab using Terraform. 

21. Navigate to the [Marketplace Console](https://us-east-1.console.aws.amazon.com/marketplace/home?region=us-west-2#/)
22. Check if Panorama is already subscribed
23. If not, go to Discover Products and search for Panorama and subscribe

24. Wait till Effective date changes from ‘Pending’ to today’s date. This will take a few minutes.

![](https://lh3.googleusercontent.com/L1M7PgFTujgp-C5XtxfQWH0MJbWHZI6nfzR8JDWz8H4chMkuzxyh422ZdpIQFw8ODE8eJXz8J_lYK4mK_-0l62MBaxR_hoDDXr4tFvQ0E7bp6frc76c19EyrjLYFeuZDyNSxKYmnL15IK1fzhg)


## Launch and prep CloudShell Environment

** In AWS CloudShell, anything saved in the home directory will persist for 90 days. Anything outside of the home directory will be wiped when the session times out. The AWS accounts for QwikLabs are re-used and the home directories are not automatically wiped. **

25. From the AWS management Console, launch CloudShell using the icon on the top right side of the console.

![](https://lh6.googleusercontent.com/taMEA5xlCYQ-oA1vhova_W0QFgZC8cLu2yavZPucn9Wt9c6rnPuCqZwJD6YuTGtYI8RXS1rgvZlzs7ndOC57DVkzKOtYMcACrNU2tCbc7lI_tq7Y6fCCDh2WtkDv622wKglzn8QiOirx43vsZg)

If you do not see the icon as shown in the image above, please check the region and ensure that you are in the _N. Virginia_ region.

26. Close out the welcome pop up.

![](https://lh5.googleusercontent.com/xKRj8zULWZouUYTzXEuYkxGHgp1On1BuSxagxKI2c0hv7YY2cgDUzXa5Pis3nrFF1ZZqG-jnmpnB9b0nbkcZwW4b-6HiB3KjI4JMbHO5bf-clM9HnrYhQv12LZXSP9kW3cCd4c3z5kJJOuBfFw)

It takes around a minute for cloudshell to launch and to get the prompt as shown in the example below.

27. After the cloudshell is launched, we will first ensure that the home directory is empty by running the below command.

```
rm -rf ~/*
```

# AWS infrastructure
clone the repo
```
git clone https://github.com/seanyoungberg/ps-aws-lab-cnf-eks.git

```

1.  Prepare CloudShell environment

Script will install Terraform, kubectl, and aws-iam-authenticator

```
sh ~/ps-aws-lab-cnf-eks/setup.sh
```

- Quality of life tweaks for working with `kubectl`

```
sudo yum install -y bash-completion
```

```
source <(kubectl completion bash) # setup autocomplete in bash into the current shell, bash-completion package should be installed first.

echo "source <(kubectl completion bash)" >> ~/.bashrc # add autocomplete permanently to your bash shell.
echo "alias k=kubectl" >> ~/.bashrc
echo "complete -o default -F __start_kubectl k}" >> ~/.bashrc
source ~/.bashrc
```


goto terraform folder
```
cd ps-aws-lab-cnf-eks/tf
```

download lambda function
```
curl -L -k https://github.com/aws-samples/eks-install-guide-for-multus/raw/main/cfn/templates/nodegroup/lambda_function.zip -O
```

Get the name of the SSH Key Pair that was generated by QwikLabs

```
aws ec2 describe-key-pairs | grep KeyName
```

Edit terraform.tfvars and add the name of the SSH Key Pair

```
key_pair = "<user>"
```

init, plan and apply
```
terraform init
terraform apply
```

# jump host preparation
go to the main folder where you cloned the repo
copy the the kernel module binaries to jump host, replace the name accordingly
```
scp -i ${QWIKLABS-key.pem} bin/igb_uio.ko bin/rte_kni.ko ubuntu@${aws-cnv3-jump-public-ip}:
```
ssh to jump host and move the files to nginx web folder
```
ssh ${aws-cnv3-jump-public-ip}
sudo mv igb_uio.ko rte_kni.ko /var/www/html/
```
\! NOTE: that these modules are specific to the ami used for the nodes, hence if you use a different ami you will most likely need to recompile the modules

# setup multus and scale the cluster
apply multus
```
kubectl apply -f https://raw.githubusercontent.com/aws/amazon-vpc-cni-k8s/master/config/multus/v3.7.2-eksbuild.1/aws-k8s-multus.yaml
```
Autoscaling group will have 0 nodes now. Scale it up. Adjust the region and name as needed
```
aws autoscaling set-desired-capacity --region eu-central-1 --auto-scaling-group-name rwe-cnv3-ng1 --desired-capacity 2
```

# panorama
Create device group and template stack that will be referenced later on. To bring up BGP peering with multus hosts deployed by TF you will need to create a template with the necessary VR/BGP/interface configuration. The cli commands creating these are in the *panorama_bgp_template.cli* file. Reference that template in the template stack.

# Helm

Helm Install

```
sudo yum install openssl
curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
chmod 700 get_helm.sh
./get_helm.sh
```

create the helm values file: eks-h.yaml, something like:
```
---
common:
  cr: "gcr.io/gcp-gcs-tse/cn-series"
  versionPanos: "10.2.0-c395"
  versionInit: "3.0.0-b3"
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

create pull secret for gcr registry, you need the sa json file. Add a password of your choise
```
kubectl -n kube-system create secret docker-registry gcr-json-key \
                --docker-server=gcr.io \
                --docker-username=_json_key \
                --docker-password="" \
                --docker-email=doesnotexist@doesnotexist.com.or.eu
```

install replace **mycn** with something else if you so desire
```
helm install mycn cnv3 --values eks-h.yaml
```

# secondary IPs and routes
you can create an alias or a convenient function in your shell environment like so:
```
function awsinstbyip  { aws ec2 describe-instances --region eu-central-1 --filter Name=private-ip-address,Values=$1 | jq '.Reservations[0].Instances[0] | {"id":.InstanceId, "ni": .NetworkInterfaces | [.[] | {"di":.Attachment.DeviceIndex,"ip":.PrivateIpAddress,"eni":.NetworkInterfaceId} ] | sort_by(.di)}'; }
```

## secondary IPs for HA
Secondary IP addresses of the ha2 link 172.16.3.101 and 172.16.3.102 should be now assigned to K8S nodes hosting the dp-0 and dp-1 accordingly (in my case .172 and .247). First run and check on which hosts are the DP-0 and DP-1. 
```
kubectl -n kube-system get pods
```
Adjust the IPs .172 and .247 in the commands below accordingly
```
dp0node=172.16.1.172
dp1node=172.16.1.247
aws ec2 assign-private-ip-addresses --region eu-central-1 --allow-reassignment \
    --private-ip-addresses 172.16.3.101 \
    --network-interface-id $(awsinstbyip $dp0node | jq -r '.ni[1].eni')

aws ec2 assign-private-ip-addresses --region eu-central-1  --allow-reassignment \
    --private-ip-addresses 172.16.3.102 \
    --network-interface-id $(awsinstbyip $dp1node | jq -r '.ni[1].eni')
```

## secondary IPs for traffic
Find the K8S node hosting the active DP pod, we will save it into *nip* variable to avoid putting it into too many places
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
aws  ec2 create-route   --region eu-central-1 --destination-cidr-block 172.17.4.0/25 \
    --route-table-id $rt \
    --network-interface-id $(awsinstbyip $nip | jq -r '.ni[3].eni')
aws  ec2 create-route   --region eu-central-1 --destination-cidr-block 172.17.5.0/25 \
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

