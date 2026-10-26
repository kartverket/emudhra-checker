# Scan Skiperator resources

[Skiperator](https://github.com/kartverket/skiperator) is an open-source
Kubernetes operator. Its `Application` and `SKIPJob` resources name the images
that run in the cluster. Skiperator makes Deployments, Jobs and CronJobs from
these resources.

Export the `Application` and `SKIPJob` resources directly, not the workloads
that Skiperator makes. Then the report shows the kind and name of the
Skiperator resource, and each image shows once per resource.

## Image fields

Each resource can have more than one image. The export reads these fields:

| Kind | API version | Image fields |
|---|---|---|
| `Application` | `v1alpha1` | `.spec.image`, `.spec.extraContainers[].image` |
| `SKIPJob` | `v1beta1` | `.spec.image`, `.spec.extraContainers[].image` |

## Export the resources

The loop needs `kubectl` and `jq`. It writes one input file for each
kubeconfig context in `CONTEXTS` (`inputs/cluster-a.txt`,
`inputs/cluster-b.txt` and so on), with one row for each image of each
resource.

```bash
CONTEXTS='cluster-a cluster-b cluster-c'
mkdir -p inputs
# $(echo ...) splits the list in both bash and zsh.
for context in $(echo "$CONTEXTS"); do
  kubectl --context "$context" get \
    applications.skiperator.kartverket.no,skipjobs.skiperator.kartverket.no -A -o json |
    jq -r '.items[] as $item
      | [$item.spec.image, ($item.spec.extraContainers // [])[].image][]
      | select(. != null and . != "")
      | [$item.metadata.namespace, $item.metadata.name, ., $item.kind]
      | @csv' > "inputs/$context.txt"
done
```

The rows have the format that the scanner reads:

```csv
"shop","web","registry.example.com/team/web:1.4.0","Application"
"shop","web","registry.example.com/team/proxy:2.0","Application"
"ops","backup","registry.example.com/team/backup:3.1","SKIPJob"
```

## Add workloads that Skiperator does not manage

A cluster can also run workloads that do not come from Skiperator. To add
them, append the generic export from the README to the same file. Exclude
the workloads that Skiperator makes with the label
`app.kubernetes.io/managed-by=skiperator`, or each image shows twice:

```bash
for context in $(echo "$CONTEXTS"); do
  kubectl --context "$context" get deployments,statefulsets,daemonsets,cronjobs -A \
    -l 'app.kubernetes.io/managed-by!=skiperator' -o json |
    jq -r '.items[] as $item
      | ($item.spec.template.spec // $item.spec.jobTemplate.spec.template.spec) as $pod
      | (($pod.initContainers // []) + ($pod.containers // []))[]
      | [$item.metadata.namespace, $item.metadata.name, .image, $item.kind]
      | @csv' >> "inputs/$context.txt"
done
```

## Scan

Scan all input files with the `-f` loop from
[Usage](../README.md#usage).
