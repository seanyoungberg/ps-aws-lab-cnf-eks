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
  default = "eu-central-1"
  type = string
}

variable "safe_ips" {
  default = [
    "34.99.77.241/32",      #prisma nl central
    "34.99.77.242/32",      #prisma nl central
    "54.241.37.235/32",     #prisma us west
    "83.242.74.253/32",     #amsterdam-gw
    "84.207.227.0/28",      #amsterdam-gw
    "84.207.230.24/29",     #amsterdam lab
    "134.238.0.0/16",       #pan /16
    "213.39.97.34/32",      #amsterdam-gp
  ]
  type = list
}

variable "owner" {
  type = string
}

variable "key_pair" {
  type = string
}
