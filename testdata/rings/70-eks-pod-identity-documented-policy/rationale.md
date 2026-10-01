# 70 — AWS's own trust policy for EKS Pod Identity

The trust policy the Amazon EKS user guide prints for a role EKS Pod Identity assumes for pods, as
written: the service principal `pods.eks.amazonaws.com` on `sts:AssumeRole` and `sts:TagSession`,
with no condition.

**Expected.** The one grant → **cloud services**, unknown, basis `service-intermediary`. The line
says the service can assume the role for pods of EKS clusters, and that who they are is not read. The
grant admits `pods.eks.amazonaws.com`, acting for whoever can make it act. The ring of anyone holds no
grant and is **unknown** beside the line.

**Why.** EKS Pod Identity assumes the role and passes its credentials to the pods whose service
account an association maps to the role. The associations are set in each cluster, which the policy
does not carry, so the role is a door and who comes through it is not read. The words say pods of
EKS clusters and name no place: the Pod Identity Agent runs on EKS Hybrid Nodes, on premises, as
well as on Amazon EC2, though the Pod Identity page itself says Pod Identities are not available for
pods anywhere but Linux EC2 instances. The line cites the first four sentences below.

> "EKS Pod Identity uses AssumeRole to assume the IAM role before passing the temporary credentials to your pods." — https://docs.aws.amazon.com/eks/latest/userguide/pod-id-role.html · read 2026-09-27
> "Each EKS Pod Identity association maps a role to a service account in a namespace in the specified cluster." — https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html · read 2026-09-27
> "If you have the same application in multiple clusters, you can make identical associations in each cluster without modifying the trust policy of the role." — https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html · read 2026-09-27
> "Each Kubernetes service account in a cluster can be associated with one IAM role from the same AWS account as the cluster." — https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html · read 2026-09-27
> "You can’t use EKS Pod Identities with: Pods that run anywhere except Linux Amazon EC2 instances." — https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html · read 2026-09-27
> "The following AWS add-ons are compatible with Amazon EKS Hybrid Nodes." — https://docs.aws.amazon.com/eks/latest/userguide/hybrid-nodes-add-ons.html · read 2026-09-27
> "As IMDS isn’t available on hybrid nodes, starting with version 1.3.3-eksbuild.1, the Pod Identity Agent add-on optionally deploys a DaemonSet that mounts the required credentials." — https://docs.aws.amazon.com/eks/latest/userguide/hybrid-nodes-add-ons.html · read 2026-09-27
> "With Amazon EKS Hybrid Nodes, you can use your on-premises and edge infrastructure as nodes in Amazon EKS clusters." — https://docs.aws.amazon.com/eks/latest/userguide/hybrid-nodes-overview.html · read 2026-09-27
