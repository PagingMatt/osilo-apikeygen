open Core.Std

let commands =
  Command.group
    ~summary:"CLI for generating Osilo service client API keys"
    []

let () = 
  Command.run
    ~version:"0.1"
    ~build_info:"osilo-apikeygen"
    commands
