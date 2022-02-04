

data "aws_eks_cluster" "cluster" {
  name = module.eks.cluster_id
}

data "aws_eks_cluster_auth" "cluster" {
  name = module.eks.cluster_id
}

data "aws_ami" "eks" {
  most_recent      = true
  owners           = ["amazon"]
  filter {
    name   = "name"
    values = ["amazon-eks-node-1.19-v202106*"]
  }
}
data "aws_ami" "ubuntu" {
  most_recent = true
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  owners = ["099720109477"]
}
data "aws_availability_zones" "azs" {
  state = "available"
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Creator = var.owner,
      Project = var.cluster_name
    }
  }
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.cluster.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.cluster.certificate_authority.0.data)
  exec {
    api_version = "client.authentication.k8s.io/v1alpha1"
    args        = ["eks", "get-token", "--cluster-name", var.cluster_name]
    command     = "aws"
  }
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "3.10.0"

  name                    = var.vpc_name
  cidr                    = "172.16.0.0/16"
  azs                     = slice(data.aws_availability_zones.azs.names, 0, 2)
  private_subnets         = ["172.16.1.0/24", "172.16.2.0/24"]
  public_subnets          = ["172.16.8.0/24"]
  single_nat_gateway      = true
  enable_nat_gateway      = true
  enable_dns_hostnames    = true
  map_public_ip_on_launch = false

  public_subnet_tags = {
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    "kubernetes.io/role/elb"                      = "1"
  }

  private_subnet_tags = {
    "kubernetes.io/cluster/${var.cluster_name}" = "shared"
    "kubernetes.io/role/internal-elb"             = "1"
  }
}
resource "aws_subnet" "multus-ha" {
  vpc_id     = module.vpc.vpc_id
  cidr_block = "172.16.3.0/24"
  availability_zone = data.aws_availability_zones.azs.names[0]
  tags = {
    Name = "${var.vpc_name}-multus-ha"
  }
}
resource "aws_subnet" "multus-1" {
  vpc_id     = module.vpc.vpc_id
  cidr_block = "172.16.4.0/24"
  availability_zone = data.aws_availability_zones.azs.names[0]
  tags = {
    Name = "${var.vpc_name}-multus-1"
  }
}
resource "aws_subnet" "multus-2" {
  vpc_id     = module.vpc.vpc_id
  cidr_block = "172.16.5.0/24"
  availability_zone = data.aws_availability_zones.azs.names[0]
  tags = {
    Name = "${var.vpc_name}-multus-2"
  }
}

resource "aws_security_group_rule" "eks_nodes" {
  description       = "nodes hitting api"
  type              = "ingress"
  from_port         = 0
  to_port           = 65535
  protocol          = "tcp"
  cidr_blocks       = module.vpc.private_subnets_cidr_blocks
  security_group_id = module.eks.cluster_primary_security_group_id
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "17.24.0"

  cluster_name    = var.cluster_name
  cluster_version = "1.19"
  vpc_id          = module.vpc.vpc_id
  subnets         = module.vpc.private_subnets
  cluster_endpoint_public_access_cidrs = var.safe_ips
  cluster_endpoint_public_access  = true  #just to have it explicitly
  cluster_endpoint_private_access = true
  map_roles = [
    {
      rolearn = aws_iam_role.eks_ir.arn
      username = "system:node:{{EC2PrivateDNSName}}"
      groups = [
      "system:bootstrappers",
      "system:nodes"
      ]
    }
  ]

  write_kubeconfig       = true
  kubeconfig_output_path = var.kubeconfig_output_path
  manage_aws_auth = true
}


resource "aws_iam_role" "eks_ir" {
  name = "${var.cluster_name}-eks_ir"
  path = "/"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })
  managed_policy_arns = [
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    "arn:aws:iam::aws:policy/AWSCloudFormationFullAccess",
  ]
}
resource "aws_iam_role_policy" "eks_iam_role_policy" {
  name   = "${var.cluster_name}-eks_iam_role_policy"
  role = aws_iam_role.eks_ir.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "ec2:AssignPrivateIpAddresses",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeSubnets",
          "ec2:ModifyInstanceAttribute",
          "ec2:ReplaceRoute",
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "eks_ip" {
  name = "${var.cluster_name}-eks_ip"
  role = aws_iam_role.eks_ir.name
}

resource "aws_launch_configuration" "eks_lc" {
  name_prefix  = "${var.cluster_name}-eks_lc"
  image_id      = data.aws_ami.eks.id
  instance_type = "m5.xlarge"   #need at least 4 interfaces
  key_name      = var.key_pair
  security_groups = [aws_security_group.eks_node_sg.id]
  iam_instance_profile = aws_iam_instance_profile.eks_ip.id
  lifecycle {
    create_before_destroy = true
  }
  user_data = <<-EOF
    #!/bin/bash
    set -o xtrace
    yum install -y golang git pciutils tcpdump
    git clone https://github.com/containernetworking/plugins
    HOME=/root /plugins/build_linux.sh
    echo -e '[Unit]\nDescription=dhcp for cni\n[Service]\nExecStart=/plugins/bin/dhcp daemon\n[Install]\nWantedBy=multi-user.target' >> /etc/systemd/system/ipam-dhcp.service
    systemctl enable --now ipam-dhcp
    echo "vm.nr_hugepages = 1024" | tee -a /etc/sysctl.conf
    /etc/eks/bootstrap.sh ${var.cluster_name} --kubelet-extra-args '--node-labels=is_worker=true'
    /opt/aws/bin/cfn-signal --exit-code $? \
             --stack  dummy_todo \
             --resource NodeGroup  \
             --region ${var.region}
    echo "net.ipv4.conf.default.rp_filter = 0" | tee -a /etc/sysctl.conf
    echo "net.ipv4.conf.all.rp_filter = 0" | tee -a /etc/sysctl.conf
    sudo sysctl -p
    sleep 45
    ls /sys/class/net/ > /tmp/ethList;cat /tmp/ethList |while read line ; do sudo ifconfig $line up; done
    grep eth /tmp/ethList |while read line ; do echo "ifconfig $line up" >> /etc/rc.d/rc.local; done
    systemctl enable rc-local
    chmod +x /etc/rc.d/rc.local
    #prepare for the dpdk
    echo ${aws_instance.jump_host.private_ip} jumphost >> /etc/hosts
    modprobe uio
    for i in igb_uio.ko rte_kni.ko; do
      wget http://jumphost/$i -O /root/$i
      insmod /root/$i
    done
    EOF
}


resource "aws_autoscaling_group" "ng1" {
  name                 = "${var.cluster_name}-ng1"
  launch_configuration = aws_launch_configuration.eks_lc.name
  min_size             = 0
  max_size             = 3
  tags = [
    {
      key = "kubernetes.io/cluster/${var.cluster_name}"
      value = "owned"
      propagate_at_launch = true
    }
  ]
  vpc_zone_identifier = [module.vpc.private_subnets[0]]
}

resource "aws_s3_bucket" "lambda_bucket" {
  bucket = "${var.cluster_name}-bucket"
  acl    = "private"
}

resource "aws_s3_bucket_object" "lambda_file" {
  bucket = aws_s3_bucket.lambda_bucket.bucket
  key    = "lambda_file"
  source = "lambda_function.zip"
  etag = filemd5("lambda_function.zip")
}

resource "aws_iam_role" "lambda_iam_role" {
  name = "${var.cluster_name}-lambda_iam_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      },
    ]
  })
}
resource "aws_iam_policy" "lambda_iam_policy" {
  name   = "${var.cluster_name}-lambda_iam_policy"
  path   = "/"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "autoscaling:CompleteLifecycleAction",
          "autoscaling:DescribeAutoScalingGroups",
          "ec2:AttachNetworkInterface",
          "ec2:CreateNetworkInterface",
          "ec2:CreateTags",
          "ec2:DeleteNetworkInterface",
          "ec2:DeleteTags",
          "ec2:DescribeInstances",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeSubnets",
          "ec2:DetachNetworkInterface",
          "ec2:ModifyNetworkInterfaceAttribute",
          "ec2:TerminateInstances"
        ]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "arn:aws:logs:*:*:*"
      },
      {
         Effect = "Allow"
         Action = "logs:CreateLogGroup"
         Resource = "arn:aws:logs:*:*:*"
      }
    ]
  })
}
resource "aws_iam_role_policy_attachment" "lambda_role_attachment" {
  role       = aws_iam_role.lambda_iam_role.name
  policy_arn = aws_iam_policy.lambda_iam_policy.arn
}
resource "aws_lambda_function" "eni_lambda" {
  function_name = "${var.cluster_name}-eni_lambda"
  role          = aws_iam_role.lambda_iam_role.arn
  handler       = "lambda_function.lambda_handler"
  s3_bucket     = aws_s3_bucket.lambda_bucket.bucket
  s3_key        = aws_s3_bucket_object.lambda_file.key
  timeout       = 60

  source_code_hash = filebase64sha256("lambda_function.zip")

  runtime = "python3.8"

  environment {
    variables = {
      SubnetIds   = join(",", [aws_subnet.multus-ha.id, aws_subnet.multus-1.id, aws_subnet.multus-2.id])
      SecGroupIds = aws_security_group.eks_node_sg.id
    }
  }
}
resource "aws_cloudwatch_event_rule" "watch_asg" {
  name        = "${var.cluster_name}-eventrule"
  description = "rwe"

  event_pattern = jsonencode({
    source = [
      "aws.autoscaling"
    ]
    detail = {
      AutoScalingGroupName = [
#        module.eks.node_groups["ng1"].node_group_name
#        module.eks.aws_autoscaling_group.workers[0]
        aws_autoscaling_group.ng1.name
      ]
    }
    detail-type = [
      "EC2 Instance-launch Lifecycle Action",
      "EC2 Instance-terminate Lifecycle Action"
    ]
  })
}
resource "aws_cloudwatch_event_target" "tl" {
  rule      = aws_cloudwatch_event_rule.watch_asg.name
  target_id = "${var.cluster_name}-et"
  arn       = aws_lambda_function.eni_lambda.arn
}
resource "aws_lambda_permission" "allow_cloudwatch" {
  statement_id = "${var.cluster_name}-lp"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.eni_lambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.watch_asg.arn
}

resource "aws_autoscaling_lifecycle_hook" "lh_launch" {
  name                   = "${var.cluster_name}-lh_launch"
  autoscaling_group_name = aws_autoscaling_group.ng1.name
  default_result         = "ABANDON"
  heartbeat_timeout      = 300
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_LAUNCHING"
}
resource "aws_autoscaling_lifecycle_hook" "lh_terminate" {
  name                   = "${var.cluster_name}-lh_terminate"
  autoscaling_group_name = aws_autoscaling_group.ng1.name
  default_result         = "ABANDON"
  heartbeat_timeout      = 300
  lifecycle_transition   = "autoscaling:EC2_INSTANCE_TERMINATING"
}

#TODO: LambdaReStartFunction
#https://github.com/aws-samples/eks-install-guide-for-multus/blob/main/cfn/templates/nodegroup/eks-nodegroup-multus.yaml

resource "aws_security_group" "corporate_ips" {
  name        = "${var.cluster_name}-fw-corporate"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description      = "ssh"
    from_port        = 22
    to_port          = 22
    protocol         = "tcp"
    cidr_blocks      = var.safe_ips
  }
  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }
}
resource "aws_security_group" "jump_sg" {
  name        = "${var.cluster_name}-jump-inbound"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description      = "web"
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    cidr_blocks      = [module.vpc.vpc_cidr_block]
  }
}
resource "aws_security_group" "eks_node_sg" {
  name        = "${var.cluster_name}-node_sg"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description      = "vpc IPs"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = concat(
                        module.vpc.private_subnets_cidr_blocks,
                        module.vpc.public_subnets_cidr_blocks,
                        [ aws_subnet.multus-ha.cidr_block,
                          aws_subnet.multus-1.cidr_block,
                          aws_subnet.multus-2.cidr_block,
                          "172.17.0.0/16",
                        ],
                      )
  }
  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
  }
}

data "template_cloudinit_config" "jh_ci" {
  gzip          = true
  base64_encode = true

  part {
    filename     = "init.cfg"
    content_type = "text/cloud-config"
    content      = <<-EOF
      #cloud-config
      packages:
        - nginx
      EOF
  }
}

resource "aws_instance" "jump_host" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"
  key_name      = var.key_pair

  subnet_id                   = module.vpc.public_subnets[0]
  vpc_security_group_ids      = [ aws_security_group.corporate_ips.id, aws_security_group.jump_sg.id ]

  user_data_base64 = "${data.template_cloudinit_config.jh_ci.rendered}"

  tags = {
    Name = "${var.cluster_name}-jump"
  }
  lifecycle {
    ignore_changes = [ami]
  }
}


data "template_cloudinit_config" "m1_ci" {
  gzip          = true
  base64_encode = true

  part {
    filename     = "init.cfg"
    content_type = "text/cloud-config"
    content      = <<-EOF
      #cloud-config
      write_files:
        - path: /etc/netplan/90-local.yaml
          content: |
            network:
              version: 2
              ethernets:
                lo:
                  addresses:
                  - 172.17.4.200/32
                ens5:
                  dhcp4: yes
                ens6:
                  dhcp4: yes
                  dhcp4-overrides:
                    use-routes: false
                  routes:
                  - to: 172.16.5.0/24
                    via: 172.16.4.199
                  - to: 172.17.5.0/24
                    via: 172.16.4.1
        - path: /etc/bird/bird.conf
          content: |
            router id 172.16.4.200;

            log "/var/log/bird/bird.log" all;
            debug protocols {events,states};

            protocol device {
              scan time 10;
              import all;
            }
            protocol direct {
              interface "lo";
            }
            protocol kernel {
              export all;
              import all;
              scan time 15;
            }
            protocol bgp pan {
              import filter {
                    accept;
              };
              export filter {
                if ( net = 172.17.4.200/32 ) then {
                    print "accepted:", net;
                    accept;
                }
                print "rejected:", net;
                reject;
              };
              local as 65431;
              source address 172.16.4.200;
              graceful restart on;
              neighbor 172.16.4.199 as 65430;
            }
            protocol bgp m2 {
              import filter {
                    accept;
              };
              local as 65431;
              source address 172.17.4.200;
              graceful restart on;
              multihop;
              neighbor 172.17.5.200 as 65432;
            }
        - path: /var/lib/cloud/scripts/per-once/bird.sh
          content: |
            #!/bin/bash
            set -o xtrace
            mkdir /var/log/bird
            touch /var/log/bird/bird.log
            chown -R bird:bird /var/log/bird
            systemctl restart bird
          permissions: '0744'
      runcmd:
        - netplan apply
      packages:
        - bird
        - fping
        - net-tools
      EOF
  }
}
resource "aws_instance" "m1_host" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"
  key_name      = var.key_pair

  subnet_id                   = module.vpc.public_subnets[0]
  vpc_security_group_ids      = [ aws_security_group.corporate_ips.id, aws_security_group.eks_node_sg.id ]

  user_data_base64 = "${data.template_cloudinit_config.m1_ci.rendered}"

  tags = {
    Name = "${var.cluster_name}-multus-1"
  }
  lifecycle {
    ignore_changes = [ami]
  }
}


data "template_cloudinit_config" "m2_ci" {
  gzip          = true
  base64_encode = true

  part {
    filename     = "init.cfg"
    content_type = "text/cloud-config"
    content      = <<-EOF
      #cloud-config
      write_files:
        - path: /etc/netplan/90-local.yaml
          content: |
            network:
              version: 2
              ethernets:
                lo:
                  addresses:
                  - 172.17.5.200/32
                ens5:
                  dhcp4: yes
                ens6:
                  dhcp4: yes
                  dhcp4-overrides:
                    use-routes: false
                  routes:
                  - to: 172.16.4.0/24
                    via: 172.16.5.199
                  - to: 172.17.4.0/24
                    via: 172.16.5.1
        - path: /etc/bird/bird.conf
          content: |
            router id 172.16.5.200;

            log "/var/log/bird/bird.log" all;
            debug protocols {events,states};

            protocol device {
              scan time 10;
              import all;
            }
            protocol direct {
              interface "lo";
            }
            protocol kernel {
              export all;
              import all;
              scan time 15;
            }
            protocol bgp pan {
              import filter {
                    accept;
              };
              export filter {
                if ( net = 172.17.5.200/32 ) then {
                    print "accepted:", net;
                    accept;
                }
                print "rejected:", net;
                reject;
              };
              local as 65432;
              source address 172.16.5.200;
              graceful restart on;
              neighbor 172.16.5.199 as 65430;
            }
            protocol bgp m1 {
              import filter {
                    accept;
              };
              local as 65432;
              source address 172.17.5.200;
              graceful restart on;
              multihop;
              neighbor 172.17.4.200 as 65431;
            }
        - path: /var/lib/cloud/scripts/per-once/bird.sh
          content: |
            #!/bin/bash
            set -o xtrace
            mkdir /var/log/bird
            touch /var/log/bird/bird.log
            chown -R bird:bird /var/log/bird
            systemctl restart bird
          permissions: '0744'
      runcmd:
        - netplan apply
      packages:
        - bird
        - fping
        - net-tools
      EOF
  }
}

resource "aws_instance" "m2_host" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t3.micro"
  key_name      = var.key_pair

  subnet_id                   = module.vpc.public_subnets[0]
  vpc_security_group_ids      = [ aws_security_group.corporate_ips.id, aws_security_group.eks_node_sg.id ]

  user_data_base64 = "${data.template_cloudinit_config.m2_ci.rendered}"

  tags = {
    Name = "${var.cluster_name}-multus-2"
  }
  lifecycle {
    ignore_changes = [ami]
  }
}

resource "aws_network_interface" "m1_host_eni" {
  subnet_id       = aws_subnet.multus-1.id
  private_ips     = ["172.16.4.200"]
  security_groups = [aws_security_group.eks_node_sg.id]
  source_dest_check = false

  attachment {
    instance     = aws_instance.m1_host.id
    device_index = 1
  }
}
resource "aws_network_interface" "m2_host_eni" {
  subnet_id       = aws_subnet.multus-2.id
  private_ips     = ["172.16.5.200"]
  security_groups = [aws_security_group.eks_node_sg.id]
  source_dest_check = false

  attachment {
    instance     = aws_instance.m2_host.id
    device_index = 1
  }
}

resource "aws_eip" "eip_jump" {
  vpc                       = true
  network_interface         = aws_instance.jump_host.primary_network_interface_id
}
resource "aws_eip" "eip_m1_host" {
  vpc                       = true
  network_interface         = aws_instance.m1_host.primary_network_interface_id
}
resource "aws_eip" "eip_m2_host" {
  vpc                       = true
  network_interface         = aws_instance.m2_host.primary_network_interface_id
}
