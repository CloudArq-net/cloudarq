# 67 — AWS's own trust policy for the IoT credentials provider

The trust policy the AWS IoT Core developer guide prints for the role its credentials provider
assumes for a device, as written: the service principal `credentials.iot.amazonaws.com` on
`sts:AssumeRole`, with no condition. Its `Statement` is one object, not a list.

**Expected.** The one grant → **cloud services**, unknown, basis `service-intermediary`. The line
says the service can assume the role for devices holding a certificate, and that who they are is not
read. The grant admits `credentials.iot.amazonaws.com`, acting for whoever can make it act. The ring
of anyone holds no grant and is **unknown** beside the line.

**Why.** The credentials provider takes a device's X.509 certificate as its identity, assumes the
role on the device's behalf, and returns the session to the device, whose requests AWS then
authorises against the role's policies. Which certificates it accepts, and for which role alias, is
set in AWS IoT, which the policy does not carry, so the role is a door and who comes through it is
not read. The line cites the first three sentences below.

> "AWS IoT Core has a credentials provider that allows you to use the built-in X.509 certificate as the unique device identity to authenticate AWS requests." — https://docs.aws.amazon.com/iot/latest/developerguide/authorizing-direct-aws.html · read 2026-09-27
> "Configure the IAM role that the credentials provider assumes on behalf of your device." — https://docs.aws.amazon.com/iot/latest/developerguide/authorizing-direct-aws.html · read 2026-09-27
> "The requested service invokes IAM to validate the signature and authorize the request against access policies attached to the IAM role that you created for the credentials provider." — https://docs.aws.amazon.com/iot/latest/developerguide/authorizing-direct-aws.html · read 2026-09-27
> "The credentials provider returns the security token to the device." — https://docs.aws.amazon.com/iot/latest/developerguide/authorizing-direct-aws.html · read 2026-09-27
