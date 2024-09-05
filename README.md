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
1. Create a new branch (git checkout -b feature-branch).
2. Commit your changes (git commit -am 'Add new feature').
3. Push the branch (git push origin feature-branch).
4. Open a pull request.

Code Inspirations:

Winterfell GitHub Repository: https://github.com/facebook/winterfell/tree/main/verifier

Winterfell official documentation: https://docs.rs/winterfell/latest/winterfell/index.html

Stark articles: 

  https://medium.com/starkware/stark-math-the-journey-begins-51bd2b063c71
  
  https://starkware.co/wp-content/uploads/2022/05/STARK-paper.pdf
  
  https://medium.com/coinmonks/zk-starks-create-verifiable-trust-even-against-quantum-computers-dd9c6a2bb13d
  
  https://hackmd.io/@liamzebedee/H1ejQCoHj
  
License
  This project is licensed under the MIT License.
   
