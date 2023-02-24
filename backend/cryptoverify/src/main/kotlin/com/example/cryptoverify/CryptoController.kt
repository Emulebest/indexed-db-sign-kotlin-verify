package com.example.cryptoverify

import org.springframework.web.bind.annotation.CrossOrigin
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.*

data class Data (
    val data: String,
    val sig: String,
    val pubKey: String
)

const val keySize = 2048

fun verifySignature(publicKeyString: String, signature: String, data: String): Boolean {

    // Create an X509EncodedKeySpec from the byte array
    val keySpec = X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyString))

    // Create a KeyFactory using the RSA algorithm
    val keyFactory = KeyFactory.getInstance("RSA")

    // Generate a public key from the X509EncodedKeySpec
    val publicKey = keyFactory.generatePublic(keySpec)

    // Verify that the key size of the imported public key matches the specified key size
    if (publicKey is java.security.interfaces.RSAPublicKey && publicKey.modulus.bitLength() != keySize) {
        throw IllegalArgumentException("The imported public key has an incorrect key size")
    }

    // Decode the base64-encoded signature string to a byte array
    val signatureBytes = Base64.getDecoder().decode(signature)

    // Convert the data string to a byte array
    val dataBytes = data.toByteArray()

    // Create a SHA-512 Signature object and initialize it with the public key
    val sha512withRSA = Signature.getInstance("SHA512withRSA")
    sha512withRSA.initVerify(publicKey)

    // Update the Signature object with the data to be verified
    sha512withRSA.update(dataBytes)

    // Verify the signature and return the result
    return sha512withRSA.verify(signatureBytes)
}

@RestController
class CryptoController {

    @CrossOrigin
    @PostMapping("/")
    fun verify(@RequestBody body: Data): String {
        val result = verifySignature(body.pubKey, body.sig, body.data)
        return if (result) "Signature verified" else "Signature verification failed"
    }

}