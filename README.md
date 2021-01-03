# jp
Search through json using PCRE2



## Building
### Linux
Prerequisites:
- build-essential debian package or equivalent
- automake

To build run `./configure` then `make`.

## Installing
If building succeeds, an executable should be built in the base of the repo. Put it in your shell's path or do with it what you wish.


---
# Usage
Attempts PCRE2 matches against values (and optionally keys) and returns match location in [jsonpath](https://goessner.net/articles/JsonPath/) (optionally returns value found at jsonpath).
Can optionally accept standard input using the filename `-`.

## Example:

    $ kubectl get pvc pmm-client-backups -o json | jp - "ReadWrite"
    .metadata.annotations.kubectl.kubernetes.io/last-applied-configuration
    .spec.accessModes[0]
    .status.accessModes[0]

    $ curl -s https://api.github.com/repos/kubernetes/kubernetes/issues | jp - "[cC]layton"
    [22].assignee.login
    [22].assignee.url
    [22].assignee.html_url
    [22].assignee.followers_url
    [22].assignee.following_url
    [22].assignee.gists_url
    [22].assignee.starred_url
    [22].assignee.subscriptions_url
    [22].assignee.organizations_url
    [22].assignee.repos_url
    [22].assignee.events_url
    [22].assignee.received_events_url
    [22].assignees[0].login
    [22].assignees[0].url
    [22].assignees[0].html_url
    [22].assignees[0].followers_url
    [22].assignees[0].following_url
    [22].assignees[0].gists_url
    [22].assignees[0].starred_url
    [22].assignees[0].subscriptions_url
    [22].assignees[0].organizations_url
    [22].assignees[0].repos_url
    [22].assignees[0].events_url
    [22].assignees[0].received_events_url
    [22].body
    
    $ jp --help
    Usage: jp [OPTION...] FILE PCRE2_EXP
    Search json with pcre2
    When [FILE] is -, read standard input

      -k, --keys                 Search keys
      -v, --values               Show results values
      -?, --help                 Give this help list
          --usage                Give a short usage message
      -V, --version              Print program version
