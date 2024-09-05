use winterfell::math::{fields::f128::BaseElement, FieldElement, ToElements};
use winterfell::{TraceTable, Air, AirContext, Assertion, EvaluationFrame, ProofOptions, TraceInfo,
    TransitionConstraintDegree, DefaultConstraintEvaluator, DefaultTraceLde, Prover, StarkDomain, Trace,
    TracePolyTable, FieldExtension, Proof, AuxRandElements, verify, AcceptableOptions};
use winterfell::crypto::{hashers::Blake3_256, DefaultRandomCoin};
use winterfell::matrix::ColMatrix;
use std::time::Instant;
use blake3::Hasher;
use std::env;
use k256::ecdsa::{SigningKey, signature::Signer, VerifyingKey, signature::DigestSigner};
use sha3::{Digest, Keccak256};


use tiny_keccak::{Keccak, Hasher as OtherHasher};

const TRACE_WIDTH: usize = 2; // Dos columnas en la traza: una para 'a' y otra para 'b': usize = 2; 


pub fn build_square_trace(start: BaseElement, n: usize) -> TraceTable<BaseElement> {
    // Instanciar la traza con un ancho de 2 (a, b) y longitud n
    let mut trace = TraceTable::new(TRACE_WIDTH, n);

    // Llenar la traza con datos; la primera columna (a) se inicializa con start
    // y la segunda columna (b) se calcula como a^2
    trace.fill(
        |state| {
            state[0] = start;            // Columna a
            state[1] = start.square();   // Columna b = a^2
        },
        |_, state| {
            // Mantener a constante y actualizar b = a^2
            state[0] = state[0] + BaseElement::new(1);             // a permanece constante
            state[1] = state[0].square();    // b = a^2
        },
    );

    trace
}

pub struct PublicInputs {
    pub start: BaseElement, // Valor inicial a
    pub result: BaseElement, // Resultado esperado b (es igual a a*a)
}

impl ToElements<BaseElement> for PublicInputs {
    fn to_elements(&self) -> Vec<BaseElement> {
        vec![self.start, self.result]
    }
}

pub struct SquareAir {
    context: AirContext<BaseElement>,
    start: BaseElement,
    result: BaseElement,
}

impl Air for SquareAir {
    type BaseField = BaseElement;
    type PublicInputs = PublicInputs;
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        assert_eq!(2, trace_info.width());

        // Define the degrees of the transition constraints
        let degrees = vec![TransitionConstraintDegree::new(2)];
        let num_assertions = 2;
        let context = AirContext::new(trace_info, degrees, num_assertions, options);
        SquareAir {
            context,
            start: pub_inputs.start,
            result: pub_inputs.result,
        }
    }

    fn evaluate_transition<E: FieldElement + From<Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current_a = frame.current()[0];
        let current_b = frame.current()[1];

        result[0] = current_a * current_a - current_b;  // Verifica que a^2 = b
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        let last_step = self.trace_length() - 1;
        vec![
            Assertion::single(0, 0, self.start),  // 'a' en el primer paso. a_0 = start
            Assertion::single(1, last_step, self.result),  // 'b' en el último paso debe ser igual a a^2. b_n-1 = result
        ]
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }
    fn get_periodic_column_values(&self) -> Vec<Vec<BaseElement>> {
        vec![]
    }
}

// We'll use BLAKE3 as the hash function during proof generation.
type Blake3 = Blake3_256<BaseElement>;

// Our prover needs to hold STARK protocol parameters which are specified via ProofOptions
// struct.
struct SquareProver {
    options: ProofOptions,
}

impl SquareProver {
    pub fn new(options: ProofOptions) -> Self {
        Self { options }
    }
}

// When implementing the Prover trait we set the `Air` associated type to the AIR of the
// computation we defined previously, and set the `Trace` associated type to `TraceTable`
// struct as we don't need to define a custom trace for our computation. For other
// associated types, we'll use default implementation provided by Winterfell.
impl Prover for SquareProver {
    type BaseField = BaseElement;
    type Air = SquareAir;
    type Trace = TraceTable<BaseElement>;
    type HashFn = Blake3;
    type RandomCoin = DefaultRandomCoin<Blake3>;
    type TraceLde<E: FieldElement<BaseField = BaseElement>> = DefaultTraceLde<E, Blake3>;
    type ConstraintEvaluator<'a, E: FieldElement<BaseField = BaseElement>> =
        DefaultConstraintEvaluator<'a, SquareAir, E>;

    // Our public inputs consist of the first and last value in the execution trace.
    fn get_pub_inputs(&self, trace: &Self::Trace) -> PublicInputs {
        let last_step = trace.length() - 1;
        PublicInputs {
            start: trace.get(0, 0),
            result: trace.get(1, last_step),
        }
    }

    // We'll use the default trace low-degree extension.
    fn new_trace_lde<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        trace_info: &TraceInfo,
        main_trace: &ColMatrix<Self::BaseField>,
        domain: &StarkDomain<Self::BaseField>,
    ) -> (Self::TraceLde<E>, TracePolyTable<E>) {
        DefaultTraceLde::new(trace_info, main_trace, domain)
    }

    // We'll use the default constraint evaluator to evaluate AIR constraints.
    fn new_evaluator<'a, E: FieldElement<BaseField = BaseElement>>(
        &self,
        air: &'a SquareAir,
        aux_rand_elements: Option<AuxRandElements<E>>,
        composition_coefficients: winterfell::ConstraintCompositionCoefficients<E>,
    ) -> Self::ConstraintEvaluator<'a, E> {
        DefaultConstraintEvaluator::new(air, aux_rand_elements, composition_coefficients)
    }

    fn options(&self) -> &ProofOptions {
        &self.options
    }
}

// Función para calcular keccak256
fn keccak256_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut output);
    output
}

fn sign_message(secret_key: &SigningKey, message_hash: &[u8]) -> k256::ecdsa::Signature {
    secret_key.sign(message_hash)
}

pub fn prove_quadratic_relation() -> (BaseElement, Proof) {
    // We'll just hard-code the parameters here for this example.
    let start = BaseElement::new(2);
    let n = 8;

    // Build the execution trace and get the result from the last step.
    let trace = build_square_trace(start, n);
    let result = trace.get(1, n - 1);


    let options = ProofOptions::new(
        32, // number of queries
        8,  // blowup factor
        0,  // grinding factor
        FieldExtension::None,
        8,   // FRI folding factor
        127, // FRI remainder max degree
    );

    // Instantiate the prover and generate the proof.
    let prover = SquareProver::new(options);
    let start_time = Instant::now(); // Inicio del tiempo
    let proof = prover.prove(trace).unwrap();
    let duration = start_time.elapsed().as_micros(); // Tiempo transcurrido

    println!("Proof generated in {:?} micros", duration);
    println!("Proof size: {} bytes", proof.to_bytes().len());
    

    


    
    (result, proof)
}


pub fn verify_quadratic_relation(start: BaseElement, result: BaseElement, proof: Proof) {
    // The verifier will accept proofs with parameters which guarantee 95 bits or more of
    // conjectured security
    let min_opts = AcceptableOptions::MinConjecturedSecurity(95);

    // The number of steps and options are encoded in the proof itself, so we don't need to
    // pass them explicitly to the verifier.
    let pub_inputs = PublicInputs {start, result };
    let proof_clone = proof.clone();
    let start_time = Instant::now();
    match verify::<SquareAir, Blake3, DefaultRandomCoin<Blake3>>(proof, pub_inputs, &min_opts) {
        Ok(_) =>{ 
            let mut hasher = blake3::Hasher::new();

            hasher.update(&proof_clone.to_bytes());
            let proof_hash = hasher.finalize();

            println!("Proof hash: {:?}", proof_hash);
            // Generar hash de la prueba (esto debería ser el mismo hash que en Solidity)
            // Calculamos el hash de la prueba usando Keccak256
            let mut hasher = Keccak256::new();
            hasher.update(&proof_clone.to_bytes());
            let proof_hash_eth = hasher.finalize();
            println!("Proof hash Ethereum: {:?}", hex::encode(proof_hash_eth));
            println!("---------------------");
            
            // Generar el prefijo Ethereum y calcular el hash final
            let eth_prefix = b"\x19Ethereum Signed Message:\n32";
            let mut eth_hasher = Keccak256::new();
            eth_hasher.update(eth_prefix);
            eth_hasher.update(proof_hash_eth);
            let eth_signed_message_hash = eth_hasher.finalize();
            
            println!("Hash firmado: {:?}", hex::encode(eth_signed_message_hash));
            println!("---------------------");
            // Inputs Públicos
            let public_inputs = PublicInputs { start, result: start.square() };
            println!("Public Inputs: {:?}{:?}", public_inputs.start, public_inputs.result);
            println!("---------------------");
            // Crear el contexto de secp256k1

            // Pares claves privada y publica
            let secret_key:SigningKey = SigningKey::from_bytes((&[0x1f; 32]).into()).expect("32 bytes, within curve order");
            let public_key = VerifyingKey::from(&secret_key);

            // Firmar el hash del mensaje usando ECDSA estándar
            let signature: k256::ecdsa::Signature = secret_key.sign(&proof_hash_eth);   

            // Convertir la firma a bytes y obtener r, s
            let sig_bytes = signature.to_bytes();
            let r = &sig_bytes[..32];
            let s = &sig_bytes[32..64];

            // Determinar el valor de v manualmente
            let v = if signature.normalize_s().is_some() { 28 } else { 27 };
            
            // Crear un arreglo de 65 bytes para la firma completa
            let mut sig_full = [0u8; 65];
            sig_full[..32].copy_from_slice(r);
            sig_full[32..64].copy_from_slice(s);
            sig_full[64] = v;
        
            // Validar que la firma tenga 65 bytes
            assert_eq!(sig_full.len(), 65, "La firma debe tener 65 bytes");

            
            // Generar hash de la clave pública para verificar en Solidity
            let binding = public_key.to_encoded_point(false);
            let public_key_bytes = binding.as_bytes();
            let public_key_hash = keccak256_hash(&public_key_bytes[1..]);
            
            //println!("Secret Key: {:?}", hex::encode(secret_key.to_bytes()));
            println!("Public Key: {:?}", public_key);
            println!("Public Key Hash Ethereum: 0x{}", hex::encode(public_key_hash));
            println!("---------------------");
            
            // Mostrar la firma en formato hexadecimal
            println!("Signature Ethereum (65 bytes): {:?}", hex::encode(sig_full));
            println!("Hash firmado: {:?}", hex::encode(eth_signed_message_hash));
            println!("---------------------");

            let duration = start_time.elapsed().as_micros();
            println!("Proof verified in {:?} micros", duration);
            println!("¡Verificación exitosa! a * a == b");
            println!("---------------------");
        },
        Err(e) => {
            println!("La verificación falló: {:?}", e);
            //println("Constraint evaluation {:?}",)
            //panic!("Error en la verificación");
        }
    }
}

fn main() {
    env::set_var("RUST_BACKTRACE", "1");
    // Imprime un mensaje de bienvenida
    println!("Iniciando el proceso de prueba y verificación utilizando Winterfell");

    // Proceso de generación de prueba
    let (result, proof) = prove_quadratic_relation();
    println!("Prueba generada con éxito.");

    let proof_hex = hex::encode(proof.to_bytes());
    println!("Proof (hex): {}", proof_hex);
    
    
    // Parámetro de inicio (debe coincidir con el utilizado en `prove_work`)
    let a = BaseElement::new(2);
    println!("---------------------");    
    // Verificación de la prueba
    verify_quadratic_relation(a,  result, proof);
    println!("Prueba verificada con éxito.");
}
