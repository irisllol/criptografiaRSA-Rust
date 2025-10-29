// Importa as partes necessárias das bibliotecas que adicionamos
use rsa::{RsaPrivateKey, RsaPublicKey, Pkcs1v15Encrypt};
use rsa::rand_core::OsRng; // Um gerador de números aleatórios seguro

fn main() {
    println!("Iniciando a geração de chaves RSA...");
    
    // --- 1. GERAÇÃO DE CHAVES ---
    // Precisamos de uma fonte de aleatoriedade segura
    let mut rng = OsRng;
    let bits = 2048; // Tamanho da chave. 2048 bits é um padrão seguro.

    // Gera a chave privada
    let private_key = RsaPrivateKey::new(&mut rng, bits)
        .expect("Erro ao gerar a chave privada Montanha");

    // Gera a chave pública a partir da chave privada
    let public_key = RsaPublicKey::from(&private_key);

    println!("Chaves geradas com sucesso Montanha!");
    println!("---------------------------------");

    // --- 2. CRIPTOGRAFIA ---
    let mensagem = b"Motanha, por favor me contrata como estagiaria. KKKKKKKKKK :D";
    println!("Mensagem original: {}", String::from_utf8_lossy(mensagem));

    // Criptografa a mensagem usando a CHAVE PÚBLICA
    // O 'padding' (preenchimento) é um esquema necessário para tornar o RSA seguro
    let padding = Pkcs1v15Encrypt;
    let mensagem_criptografada = public_key.encrypt(&mut rng, padding, &mensagem[..])
        .expect("Falha ao criptografar coisas secretas :/");

    println!("\nMensagem criptografada (em bytes): \n{:?}", mensagem_criptografada);
    println!("---------------------------------");


    // --- 3. DESCRIPTOGRAFIA ---
    
    // Descriptografa a mensagem usando a CHAVE PRIVADA
    // É importante usar o mesmo esquema de 'padding'
    let padding_dec = Pkcs1v15Encrypt;
    let mensagem_descriptografada = private_key.decrypt(padding_dec, &mensagem_criptografada)
        .expect("Falha ao descriptografar");

    println!("\nMensagem descriptografada: {}", String::from_utf8_lossy(&mensagem_descriptografada));

    // Verificação final
    assert_eq!(&mensagem[..], &mensagem_descriptografada[..]);
    println!("\nSucesso! A mensagem original e a descriptografada sao identicas Montanha :).");
}