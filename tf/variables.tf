variable "cluster_name" {
  default = "k8s"
  type = string
}

variable "vpc_name" {
  default = "k8s-vpc1"
  type = string
}

variable "kubeconfig_output_path" {
  default = "~/.kube/config"
  type = string
}

variable "region" {
  default = "us-west-2"
  type = string
}

variable "safe_ips" {
  default = [
    "0.0.0.0/0"             #everywhere for QwikLabs :)
  ]
  type = list
}

variable "owner" {
  type = string
}

variable "key_pair" {
  type = string
}


variable "management-vpc" { default = {} }
variable "management-vpc-subnets" { default = [] }
variable "management-vpc-route-tables" { default = [] }
variable "management-vpc-security-groups" { default = [] }
variable "management-vpc-routes" { default = [] }
variable "panorama" { default = {} }

variable "prefix-name-tag" {}
variable "global_tags" {}