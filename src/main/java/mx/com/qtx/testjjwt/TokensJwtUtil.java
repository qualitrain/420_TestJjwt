package mx.com.qtx.testjjwt;

import java.security.KeyPair;
import java.util.Date;
import java.util.UUID;

import javax.crypto.SecretKey;

import io.jsonwebtoken.*;

public class TokensJwtUtil {
	public static SecretKey generarLlave(AlgoritmoCifradoLlaveSimetrico algoritmo) {
		switch (algoritmo){
			case HmacSHA256: return Jwts.SIG.HS256.key().build();
			case HmacSHA384: return Jwts.SIG.HS384.key().build();
			case HmacSHA512: return Jwts.SIG.HS512.key().build();
			default: return null;
		}
		
	}
	
	public static KeyPair generarParLlaves(AlgoritmoCifradoParLlaves algoritmo) {
		switch (algoritmo){
			case EdDSA: return Jwts.SIG.EdDSA.keyPair().build();
			case ES256: return Jwts.SIG.ES256.keyPair().build();
			case ES384: return Jwts.SIG.ES384.keyPair().build();
			case ES512: return Jwts.SIG.ES512.keyPair().build();
			case PS256: return Jwts.SIG.PS256.keyPair().build();
			case PS384: return Jwts.SIG.PS384.keyPair().build();
			case PS512: return Jwts.SIG.PS512.keyPair().build();
			case RS256: return Jwts.SIG.RS256.keyPair().build();
			case RS384: return Jwts.SIG.RS384.keyPair().build();
			case RS512: return  Jwts.SIG.RS512.keyPair().build();
			default: return null;
		}
	}

	public static String generarToken(String nombreUsuario) {
		long duracionTokensMilis = 1000 * 60 * 60 * 10;
		
		String id = UUID.randomUUID()
				        .toString()
				        .replace("-", "");
		SecretKey llave = generarLlave(AlgoritmoCifradoLlaveSimetrico.HmacSHA256);
		Date ahora = new Date();
		Date expiracion = new Date(System.currentTimeMillis() + duracionTokensMilis);
		
		String tokenJwt = Jwts.builder().id(id)
	                          .issuedAt(ahora)
			                  .subject(nombreUsuario)
			                  .expiration(expiracion)
			                  .signWith(llave)
			                  .compact();
		
		return tokenJwt;
	}
}
