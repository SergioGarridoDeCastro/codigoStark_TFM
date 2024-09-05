# codigoStark_TFM
Programa que genera y verifica pruebas STARK utilizando la libreria Winterfell.


This repository contains a Rust project that leverages the Winterfell library for cryptographic operations, specifically involving STARK (Scalable Transparent Argument of Knowledge) proofs.

Features
- Implements cryptographic operations with zero-knowledge proofs.
- Utilizes Winterfell's field elements, trace tables, and proof verification methods.
- Customizes the prover logic with constraints and trace evaluation.
Requirements
- Rust (Ensure you have the latest version installed)
- Cargo (Rust's package manager)
- Winterfell crate (already listed in the dependencies)
Installation
1. Clone the repository:
  git clone https://github.com/your-username/your-repo-name.git
  cd your-repo-name
2. Build the project:
  cargo build --release   
3. Run  the project:
  cargo run

Usage
This project performs cryptographic operations involving STARK proofs. Modify the inputs in the do_work function to customize the cryptographic trace evaluation.

Contributing
- Fork the repository.
- Create a new branch (git checkout -b feature-branch).
- Commit your changes (git commit -am 'Add new feature').
- Push the branch (git push origin feature-branch).
- Open a pull request.
License
  This project is licensed under the MIT License.
   
