open Core.Std
open Osilo.Cryptography

let read_file_to_cstruct ~f =
  let open Unix in
  let buf  = String.make 65536 'x' in
  let file = Unix.openfile ~mode:[O_RDONLY] f in file
  |> Unix.read ~buf
  |> (fun l -> (Unix.close file); String.prefix buf l)
  |> Cstruct.of_string

let rsa_private_key ~key =
  read_file_to_cstruct key
  |> X509.Encoding.Pem.Private_key.of_pem_cstruct1
  |> begin function
    | `RSA prv -> prv
  end

let x509_certificate ~cert =
  read_file_to_cstruct cert
  |> X509.Encoding.Pem.Certificate.of_pem_cstruct1

let hostname hs =
  match hs with
  | h::[] -> h
  | _     -> assert false

let generate_api_key ~service ~cert ~key =
  let open Nocrypto in
  let private_key = rsa_private_key key   in
  let certificate = x509_certificate cert in
  let hs = X509.hostnames certificate     in
  Signing.sign ~key:private_key (hostname hs |> Cstruct.of_string)
  |> Serialisation.serialise_cstruct
  |> Printf.printf "%s" 

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
