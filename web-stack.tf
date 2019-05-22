# Parameters

variable "domain" {
  description = "The domain name for the site"
}

variable "primaryregion" {
  default = "us-east-1"
}

variable "os_type" {
  default = "ubuntu-nginx" # allowable values: ubuntu-nginx, centos-apache
}

variable "ubuntu_ami_id" { # Ubuntu 18.04 LTS AMI
  type = "map"
  default = {
    "us-west-2" = "ami-04ef7170e45541f07"
    "us-east-1" = "ami-0273df992a343e0d6"
    "us-east-2" = "ami-033a0960d9d83ead0"
    "us-west-1" = "ami-057a852b5ed4b66bc"
    "ca-central-1" = "ami-044530525bc7eff8e" # Canada
    "eu-west-1" = "ami-0ae0cb89fc578cd9c" # Ireland
    "ap-east-1" = "ami-9ea0d8ef" # Asia-Pacific
    "cn-north-1" = "ami-09dd6088c3e46151c" # China
    "sa-east-1" = "ami-0d6e00211f2547822" # South America
  }
}

variable "centos_ami_id" {
  type = "map"
  default = {
    "us-west-2" = "ami-a042f4d8"
    "us-east-1" = "ami-4bf3d731"
    "us-east-2" = "ami-e1496384"
    "us-west-1" = "ami-65e0e305"
    "ca-central-1" = "ami-dcad28b8" # Canada
    "eu-west-1" = "ami-6e28b517" # Ireland
    "ap-south-1" = "ami-3d9ec952" # Asia-Pacific
    "sa-east-1" = "ami-f9adef95" # South America
  }
}
# Centos does not make China image available according to their wiki: https://wiki.centos.org/Cloud/AWS

variable "aws_access_key" {}
variable "aws_secret_key" {}
variable "mysql_pass" {}

provider "aws" {
  access_key = "${var.aws_access_key}"
  secret_key = "${var.aws_secret_key}"
  region = "${var.primaryregion}"
}

resource "aws_key_pair" "keypair" {
  key_name = "ssh-keypair"
  public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCRUK0A4dLC2Ww0He1IbUPCn4AmwautKvSoM7gCB1uyAJ4sROHlxrbIceeQie3TNYAtCywARZcItqwY0UDmPSX8cxEio94qkZ9n083VrOWeTxfy7Budy03cJIL0G2TDa1E9r1Dr4HVq5akLZy6DtMSjUbUxLp8eJhnBHamRcjG9PMIcFZaW4qV/2Re9Wct6jLvkSsKi71U8NFd1ZzzbkakRz90CuBTazQS170F0KBzb5fTNgadAb7kegKmYbGkLVdz6HmGnggujx5g+QIofX7Mh2poz1RiItqlq1F7ALpJygvydElhf0dJHjEvaQeyBo16eOOLQRziUp3Fair1FOJwL aletson-personal"
}

# Resources for Terraform to build out

resource "aws_acm_certificate" "cert" {
  domain_name = "${var.domain}"
  validation_method = "DNS"
  subject_alternative_names = [ "www.${var.domain}" ]
  
  lifecycle {
    create_before_destroy = true
  }
  
}

resource "aws_vpc" "vpc" {
  cidr_block = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support = true
  tags {
    Name = "${var.domain}-vpc"
  }
}

resource "aws_internet_gateway" "gw" {
  vpc_id = "${aws_vpc.vpc.id}"
}

resource "aws_subnet" "efs_subnet_a" {
  cidr_block = "${cidrsubnet(aws_vpc.vpc.cidr_block, 8, 1)}" # 10.0.1.0/24
  vpc_id = "${aws_vpc.vpc.id}"
  availability_zone = "${var.primaryregion}a"
}
resource "aws_subnet" "efs_subnet_b" {
  cidr_block = "${cidrsubnet(aws_vpc.vpc.cidr_block, 8, 2)}" # 10.0.2.0/24
  vpc_id = "${aws_vpc.vpc.id}"
  availability_zone = "${var.primaryregion}a"
}
resource "aws_subnet" "efs_subnet_c" {
  cidr_block = "${cidrsubnet(aws_vpc.vpc.cidr_block, 8, 3)}" # 10.0.3.0/24
  vpc_id = "${aws_vpc.vpc.id}"
  availability_zone = "${var.primaryregion}a"
}
resource "aws_subnet" "efs_subnet_d" {
  cidr_block = "${cidrsubnet(aws_vpc.vpc.cidr_block, 8, 4)}" # 10.0.4.0/24
  vpc_id = "${aws_vpc.vpc.id}"
  availability_zone = "${var.primaryregion}a"
}

resource "aws_subnet" "ec2_subnet_a" {
  cidr_block = "${cidrsubnet(aws_vpc.vpc.cidr_block, 8, 5)}" # 10.0.5.0/24
  vpc_id = "${aws_vpc.vpc.id}"
  availability_zone = "${var.primaryregion}a"
}
resource "aws_subnet" "ec2_subnet_b" {
  cidr_block = "${cidrsubnet(aws_vpc.vpc.cidr_block, 8, 6)}" # 10.0.6.0/24
  vpc_id = "${aws_vpc.vpc.id}"
  availability_zone = "${var.primaryregion}b"
}
resource "aws_subnet" "ec2_subnet_c" {
  cidr_block = "${cidrsubnet(aws_vpc.vpc.cidr_block, 8, 7)}" # 10.0.7.0/24
  vpc_id = "${aws_vpc.vpc.id}"
  availability_zone = "${var.primaryregion}c"
}
resource "aws_subnet" "rds_subnet_d" {
  cidr_block = "${cidrsubnet(aws_vpc.vpc.cidr_block, 8, 8)}" # 10.0.8.0/24
  vpc_id = "${aws_vpc.vpc.id}"
  availability_zone = "${var.primaryregion}d"
}

resource "aws_subnet" "rds_subnet_c" {
  cidr_block = "${cidrsubnet(aws_vpc.vpc.cidr_block, 8, 9)}" # 10.0.9.0/24
  vpc_id = "${aws_vpc.vpc.id}"
  availability_zone = "${var.primaryregion}c"
}

resource "aws_subnet" "eca_subnet_a" {
  cidr_block = "${cidrsubnet(aws_vpc.vpc.cidr_block, 8, 10)}" # 10.0.10.0/24
  vpc_id = "${aws_vpc.vpc.id}"
  availability_zone = "${var.primaryregion}a"
}

resource "aws_subnet" "eca_subnet_b" {
  cidr_block = "${cidrsubnet(aws_vpc.vpc.cidr_block, 8, 11)}" # 10.0.11.0/24
  vpc_id = "${aws_vpc.vpc.id}"
  availability_zone = "${var.primaryregion}b"
}

resource "aws_security_group" "efs_security_group" {
  name = "efs-sg"
  vpc_id = "${aws_vpc.vpc.id}"
}

resource "aws_security_group_rule" "ingress_ec2_to_efs" {
  type = "ingress"
  from_port = 2049
  to_port = 2049
  protocol = "tcp"
  security_group_id = "${aws_security_group.efs_security_group.id}"
  source_security_group_id = "${aws_security_group.ec2_lb_group.id}"
}

resource "aws_security_group_rule" "egress_efs_to_ec2" {
  type = "egress"
  from_port = 0
  to_port = 0
  protocol = "-1"
  security_group_id = "${aws_security_group.efs_security_group.id}"
  source_security_group_id = "${aws_security_group.ec2_lb_group.id}"
}

resource "aws_security_group" "ec2_lb_group" {
  name = "ec2-instance-sg"
  vpc_id = "${aws_vpc.vpc.id}"
}

resource "aws_security_group_rule" "ingress_alb_to_ec2" {
  type = "ingress"
  from_port = 80
  to_port = 80
  protocol = "tcp"
  security_group_id = "${aws_security_group.ec2_lb_group.id}"
  source_security_group_id = "${aws_security_group.alb_group.id}"
}

resource "aws_security_group_rule" "egress_ec2_to_efs" {
  type = "egress"
  from_port = 0
  to_port = 0
  protocol = "-1"
  security_group_id = "${aws_security_group.ec2_lb_group.id}"
  source_security_group_id = "${aws_security_group.efs_security_group.id}"
}

resource "aws_security_group_rule" "egress_ec2_to_rds" {
  type = "egress"
  from_port = 0
  to_port = 0
  protocol = "-1"
  security_group_id = "${aws_security_group.ec2_lb_group.id}"
  source_security_group_id = "${aws_security_group.rds_security_group.id}"
}

resource "aws_security_group_rule" "egress_ec2_to_elasticache" {
  type = "egress"
  from_port = 0
  to_port = 0
  protocol = "-1"
  security_group_id = "${aws_security_group.ec2_lb_group.id}"
  source_security_group_id = "${aws_security_group.eca_grp.id}"
}



resource "aws_security_group" "eca_grp" {
  name = "elasticache-sg"
  vpc_id = "${aws_vpc.vpc.id}"
}

resource "aws_security_group_rule" "ingress_ec2_to_elasticache" {
  type = "ingress"
  from_port = 6379
  to_port = 6379
  protocol = "tcp"
  security_group_id = "${aws_security_group.eca_grp.id}"
  source_security_group_id = "${aws_security_group.ec2_lb_group.id}"
}

resource "aws_security_group_rule" "egress_elasticache_to_ec2" {
  type = "ingress"
  from_port = 0
  to_port = 0
  protocol = "-1"
  security_group_id = "${aws_security_group.eca_grp.id}"
  source_security_group_id = "${aws_security_group.ec2_lb_group.id}"
}

resource "aws_security_group" "alb_group" {
  name = "ec2-alb-sg"
  vpc_id = "${aws_vpc.vpc.id}"
}

resource "aws_security_group_rule" "ingress_https_to_alb" {
  type = "ingress"
  from_port = 443
  to_port = 443
  cidr_blocks = ["0.0.0.0/0"]
  protocol = "tcp"
  security_group_id = "${aws_security_group.alb_group.id}"
}

resource "aws_security_group_rule" "ingress_http_to_alb" {
  type = "ingress"
  from_port = 80
  to_port = 80
  cidr_blocks = ["0.0.0.0/0"]
  protocol = "tcp"
  security_group_id = "${aws_security_group.alb_group.id}"
}

resource "aws_security_group_rule" "egress_alb_to_all" {
  type = "ingress"
  from_port = 0
  to_port = 0
  cidr_blocks = ["0.0.0.0/0"]
  protocol = "-1"
  security_group_id = "${aws_security_group.alb_group.id}"
}

resource "aws_security_group" "rds_security_group" {
  name = "rds-sg"
  vpc_id = "${aws_vpc.vpc.id}"
}

resource "aws_security_group_rule" "ingress_ec2_to_rds" {
  type = "ingress"
  from_port = 3306
  to_port = 3306
  protocol = "tcp"
  security_group_id = "${aws_security_group.rds_security_group.id}"
  source_security_group_id = "${aws_security_group.ec2_lb_group.id}"
}

resource "aws_security_group_rule" "egress_rds_to_ec2" {
  type = "egress"
  from_port = 0
  to_port = 0
  protocol = "-1"
  security_group_id = "${aws_security_group.rds_security_group.id}"
  source_security_group_id = "${aws_security_group.ec2_lb_group.id}"
}

resource "aws_efs_file_system" "fs" {
  tags = {
    Name = "${var.domain}-efs"
  }
}

resource "aws_efs_mount_target" "fs_mount" {
  file_system_id = "${aws_efs_file_system.fs.id}"
  subnet_id = "${aws_subnet.efs_subnet_a.id}"
  security_groups = ["${aws_security_group.efs_security_group.id}"]
}

resource "aws_launch_template" "ec2_launch" {
  name = "ec2-launch"
  block_device_mappings {
    device_name = "/dev/sda1"
	
	ebs {
	  volume_size = 20
	}
  }
  
  capacity_reservation_specification {
    capacity_reservation_preference = "none"
  }
  
  credit_specification {
    cpu_credits = "standard"
  }
  
  disable_api_termination = false
  
  ebs_optimized = true
  
  image_id = "${var.os_type == "ubuntu-nginx" ? lookup(var.ubuntu_ami_id, var.primaryregion) : lookup(var.centos_ami_id, var.primaryregion)}"
  
  instance_type = "t3.micro"
  
  key_name = "${aws_key_pair.keypair.key_name}"
  
  vpc_security_group_ids = ["${aws_security_group.ec2_lb_group.id}"]
  
  user_data = "${base64encode(data.template_file.userdata.rendered)}"
  
}

data "template_file" "userdata" {
  template = "${file("${path.module}/${var.os_type == "ubuntu-nginx" ? "ubuntu" : "centos" }-userdata.sh")}"
  vars = {
    domain = "${var.domain}"
    mount_point = "${aws_efs_file_system.fs.dns_name}"
	redis = "${aws_elasticache_cluster.eca_cluster.cache_nodes.0.address}"
	database = "${aws_db_instance.rds.endpoint}"
  }
}

resource "aws_lb" "alb" {
  name = "alb"
  internal = false
  subnets = ["${aws_subnet.ec2_subnet_a.id}", "${aws_subnet.ec2_subnet_b.id}", "${aws_subnet.ec2_subnet_c.id}"]
  security_groups = ["${aws_security_group.alb_group.id}"]
}

resource "aws_lb_listener" "alb_https" {
  load_balancer_arn = "${aws_lb.alb.arn}"
  port = "443"
  protocol = "HTTPS"
  ssl_policy = "ELBSecurityPolicy-2016-08"
  certificate_arn = "${aws_acm_certificate.cert.arn}"
  
  default_action {
    type = "forward"
	target_group_arn = "${aws_lb_target_group.ec2_tg.arn}"
  }
}

resource "aws_lb_listener" "alb_http" {
  load_balancer_arn = "${aws_lb.alb.arn}"
  port = "80"
  protocol = "HTTP"
  
  default_action {
    type = "redirect"
	redirect {
	  port = "443"
	  protocol = "HTTPS"
	  status_code = "HTTP_301"
	}
  }
}

resource "aws_lb_target_group" "ec2_tg" {
  name = "targetgroup"
  port = 80
  protocol = "HTTP"
  vpc_id = "${aws_vpc.vpc.id}"
  
  stickiness {
    type = "lb_cookie"
	cookie_duration = "86400"
	enabled = true
  }
}


resource "aws_autoscaling_group" "autoscale" {
  vpc_zone_identifier = ["${aws_subnet.ec2_subnet_a.id}", "${aws_subnet.ec2_subnet_b.id}", "${aws_subnet.ec2_subnet_c.id}"]
  launch_template {
    id = "${aws_launch_template.ec2_launch.id}"
  }
  min_size = 2
  max_size = 5
  desired_capacity = 2
  target_group_arns = ["${aws_lb_target_group.ec2_tg.arn}"]
}


resource "aws_route53_zone" "zone" {
  name = "${var.domain}"
}

resource "aws_route53_record" "cert_validation" {
  name = "${aws_acm_certificate.cert.domain_validation_options.0.resource_record_name}"
  type = "${aws_acm_certificate.cert.domain_validation_options.0.resource_record_type}"
  zone_id = "${aws_route53_zone.zone.id}"
  records = ["${aws_acm_certificate.cert.domain_validation_options.0.resource_record_value}"]
  ttl = 60
}

resource "aws_route53_record" "cert_validation_www" {
  name = "${aws_acm_certificate.cert.domain_validation_options.1.resource_record_name}"
  type = "${aws_acm_certificate.cert.domain_validation_options.1.resource_record_type}"
  zone_id = "${aws_route53_zone.zone.id}"
  records = ["${aws_acm_certificate.cert.domain_validation_options.1.resource_record_value}"]
  ttl = 60
}

resource "aws_route53_record" "apex" {
  name = "${var.domain}"
  type = "A"
  zone_id = "${aws_route53_zone.zone.id}"
  
  alias {
    name = "${aws_lb.alb.dns_name}"
    zone_id = "${aws_lb.alb.zone_id}"
    evaluate_target_health = true
  }
}

resource "aws_route53_record" "www" {
  name = "www.${var.domain}"
  type = "CNAME"
  zone_id = "${aws_route53_zone.zone.id}"
  records = [ "${var.domain}" ]
  ttl = 60
}

resource "aws_acm_certificate_validation" "cert" {
  certificate_arn = "${aws_acm_certificate.cert.arn}"
  validation_record_fqdns = ["${aws_route53_record.cert_validation.fqdn}", "${aws_route53_record.cert_validation_www.fqdn}"]
}

resource "aws_db_subnet_group" "rds_subnet_group" {
  subnet_ids = ["${aws_subnet.rds_subnet_c.id}", "${aws_subnet.rds_subnet_d.id}"]
}

resource "aws_db_instance" "rds" {
  allocated_storage = 20
  storage_type = "gp2"
  engine = "mysql"
  engine_version = "5.7"
  instance_class = "db.t3.micro"
  username = "webadmin"
  password = "${var.mysql_pass}"
  vpc_security_group_ids = ["${aws_security_group.rds_security_group.id}"]
  db_subnet_group_name = "${aws_db_subnet_group.rds_subnet_group.name}"
}

resource "aws_elasticache_cluster" "eca_cluster" {
  cluster_id = "eca-cluster"
  engine = "redis"
  node_type = "cache.t2.micro"
  num_cache_nodes = 1
  parameter_group_name = "default.redis5.0"
  engine_version = "5.0.4"
  port = 6379
  security_group_ids = ["${aws_security_group.eca_grp.id}"]
  subnet_group_name = "${aws_elasticache_subnet_group.eca_subgrp.name}"
}
  
resource "aws_elasticache_subnet_group" "eca_subgrp" {
  name = "eca-subnetgroup"
  subnet_ids = ["${aws_subnet.eca_subnet_a.id}", "${aws_subnet.eca_subnet_b.id}"]
}