open Core.Std

let generate_api_key ~service ~cert ~key = ()

let gen =
  Command.basic
    ~summary:"Generate an Osilo service client API key."
    Command.Spec.(
      empty
      +> flag "-s" (required string)
        ~doc:"  Service the client is for."
      +> flag "-c" (required string)
        ~doc:"  Path to peer's x509 certificate."
      +> flag "-k" (required string)
        ~doc:"  Path to peer's private key file."
    ) (fun s c k () -> generate_api_key ~service:s ~cert:c ~key:k)

let commands =
  Command.group
    ~summary:"CLI for generating Osilo service client API keys"
    [("gen",gen)]

let () =
  Command.run
    ~version:"0.1"
    ~build_info:"osilo-apikeygen"
    commands
