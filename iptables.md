# Iptables

## Misc notes

- In the vast majority of use cases you won't need to use the `raw`, `mangle`, or `security` tables at all.
- In most common use cases you will only use two of these: `filter` and `nat`.

## Terms

- **IP masquerading**

   A technique that hides an entire IP address space, usually consisting of private IP addresses, behind a single IP address in another, usually public address space. The address that has to be hidden is changed into a single (public) IP address as "new" source address of the outgoing IP packet so it appears as originating not from the hidden host but from the routing device itself. Because of the popularity of this technique to conserve IPv4 address space, the term NAT has become virtually synonymous with IP masquerading.  

- **Stateful packet inspection (SPI)** 

   Also referred to as dynamic packet filtering, is a security feature often included in business networks.  

## Packet flow through iptables

### Simplified ASCII illustration of packet network flow through iptables

```
                               XXXXXXXXXXXXXXXXXX
                             XXX     Network    XXX
                               XXXXXXXXXXXXXXXXXX
                                       +
                                       |
                                       v
 +-------------+              +------------------+
 |table: filter| <---+        | table: nat       |
 |chain: INPUT |     |        | chain: PREROUTING|
 +-----+-------+     |        +--------+---------+
       |             |                 |
       v             |                 v
 [local process]     |           ****************          +--------------+
       |             +---------+ Routing decision +------> |table: filter |
       v                         ****************          |chain: FORWARD|
****************                                           +------+-------+
Routing decision                                                  |
****************                                                  |
       |                                                          |
       v                        ****************                  |
+-------------+       +------>  Routing decision  <---------------+
|table: nat   |       |         ****************
|chain: OUTPUT|       |               +
+-----+-------+       |               |
      |               |               v
      v               |      +-------------------+
+--------------+      |      | table: nat        |
|table: filter | +----+      | chain: POSTROUTING|
|chain: OUTPUT |             +--------+----------+
+--------------+                      |
                                      v
                               XXXXXXXXXXXXXXXXXX
                             XXX    Network     XXX
                               XXXXXXXXXXXXXXXXXX
```

### Packet chain traversal



## Tables

 - `raw` is used only for configuring packets so that they are exempt from connection tracking.
 - `filter` is the default table, and is where all the actions typically associated with a firewall take place.
 - `nant` is used for network address translation (e.g. port forwarding).
 - `mangle` is used for specialized packet alterations
 - `security` is used for Mandatory Access Control networking rules (e.g. SELinux)
 
## Chains overview

 - Tables consist of chains which contain rules that are followed in order.
 - By default, none of the chains contain any rules. It is up to you to append rules to the chains which you want to use.
 - By default, chains generally will have a default policy of `ACCEPT` but this can be changed to `DROP` to be sure nothing slips through your ruleset.
 - Packets have to successfully pass through all rules before hitting the default policy.

### Chain's in tables

- **`filter`** (default table) contains three built-in chains which are activated at different points of the packet filtering process.
  - `INPUT`
  - `OUTPUT`
  - `FORWARD`

- **`nat`** contains three chains and is used for network address translation
  - `PREROUTING`
  - `POSTROUTING`
  - `OUTPUT`

## Rules

   1. Packet filtering is based on rules, which are specified by multiple matches (conditions the packet must satisfy so that the rule can be applied), and one target (action taken when the packet matches all conditions).

### Rule targets

- Target's are specified using either the short-hand option `-j` or long-hand `--jump`
- Targets can be either user-defined chains (i.e. if these conditions are matched, jump to the following user-defined chain and continue processing there), one of the special built-in targets, or a target extension.

### Built-in rule targets

 - `ACCEPT`
 - `DROP`
 - `QUEUE`
 - `RETURN`
 - `REJECT` *(target extension)*
 - `LOG` *(target extension)*

### Notable mentions

 - If the target is a built-in target, the fate of the packet is decided immediately and processing of the packet in current table is stopped
 - If the target is a user-defined chain and the fate of the packet is not decided by this second chain, it will be filtered against the remaining rules of the original chain
 - Target extensions can be either terminating (as built-in targets) or non-terminating (as user-defined chains)

## Sources

- [Wikipedia](https://wiki.archlinux.org/index.php/Iptables#Basic_concepts)
- [Frozentux iptables tutorial](https://www.frozentux.net/iptables-tutorial/iptables-tutorial.html#TRAVERSINGOFTABLES)