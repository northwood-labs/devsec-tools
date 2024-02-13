## devsec-tools completion powershell

Generate the autocompletion script for powershell

### Synopsis

Generate the autocompletion script for powershell.

To load completions in your current shell session:

	devsec-tools completion powershell | Out-String | Invoke-Expression

To load completions for every new session, add the output of the above command
to your powershell profile.

```
devsec-tools completion powershell [flags]
```

### Options

```
  -h, --help              help for powershell
      --no-descriptions   disable completion descriptions
```

### Options inherited from parent commands

```
  -q, --quiet     Disable all logging output.
  -v, --verbose   Enable verbose output.
```

### SEE ALSO

* [devsec-tools completion](devsec-tools_completion.md)  - Generate the autocompletion script for the specified shell
