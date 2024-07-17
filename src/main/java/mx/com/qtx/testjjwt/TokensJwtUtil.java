package mx.com.qtx.testjjwt;

import java.security.KeyPair;
import java.util.Arrays;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.function.Function;

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
		SecretKey llave = generarLlave(AlgoritmoCifradoLlaveSimetrico.HmacSHA256);
		return generarToken(nombreUsuario, llave);
	}
	

	public static String generarToken(String nombreUsuario, SecretKey llave) {
		long duracionTokensMilis = 1000 * 60 * 60 * 10;
		
		String id = UUID.randomUUID()
				        .toString()
				        .replace("-", "");
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
	
	public static String generarToken(String nombreUsuario, Map<String,Object> mapClaims) {
		SecretKey llave = generarLlave(AlgoritmoCifradoLlaveSimetrico.HmacSHA512);
		return generarToken(nombreUsuario, mapClaims, llave);
	}
	
	public static String generarToken(String nombreUsuario, Map<String,Object> mapClaims, 
			                          SecretKey llave) {
		long duracionTokensMilis = 1000 * 60 * 60 * 10;
		return generarToken(nombreUsuario,mapClaims,llave,duracionTokensMilis);
	}
	
	public static String generarToken(String nombreUsuario, Map<String,Object> mapClaims, 
			                          SecretKey llave, long milisDuracion) {
		Date ahora = new Date();
		Date expiracion = new Date(System.currentTimeMillis() + milisDuracion);
		String id = UUID.randomUUID()
				        .toString()
				        .replace("-", "");
		
		Claims claims = Jwts.claims().add(mapClaims).build();
		
		return Jwts.builder()
					  .id(id)
					  .issuedAt(ahora)
					  .expiration(expiracion)
					  .subject(nombreUsuario)
					  .claims(claims)
		              .signWith(llave)
		              .compact();	
	}
	
	/**
	 * Usar con tokens firmados
	 * @param tokenFirmado
	 * @param llave
	 * @return
	 */
	public static Jws<Claims> extraerJwsClaimsTokenFirmado(String tokenFirmado, SecretKey llave){
		 JwtParser parser = Jwts.parser()
				                .verifyWith(llave)
			                    .build();
		
		 Jws<Claims> jwsClaims = parser.parseSignedClaims(tokenFirmado);

		return jwsClaims;
	}
	
	public static Jwt<Header,Claims> extraerJwtTokenSinFirmar(String tokenSinFirma){
		// Solamente se debe usar con tokens SIN firmar
		Jwt<Header,Claims> jwtHeaderClaims = Jwts.parser()
											     .build()
											     .parseUnsecuredClaims(tokenSinFirma);
		return jwtHeaderClaims;
	}

	public static String extraerContenidoTokenFirmadoStr(String tokenFirmado, SecretKey llave) {
		
		Jws<Claims> contenidoToken = extraerJwsClaimsTokenFirmado(tokenFirmado, llave);
		
		JwsHeader header = contenidoToken.getHeader();
		String strHeader = "Header:["
				      + "Algorithm:" + header.getAlgorithm() + ", "
				      + "CompressionAlgorithm:" + header.getCompressionAlgorithm() + ", "
				      + "ContentType:" + header.getContentType() + ", "
				      + "KeyId(protected header):" + header.getKeyId() + ", "
				      + "Type:" + header.getType() 
				      + "] ";
		
		 Claims payload = contenidoToken.getPayload();
		 String strPayload = "Payload:["
				           + "Id:" + payload.getId( )+ ", "
				           + "Issuer:" + payload.getIssuer() + ", "
                           + "Subject:" + payload.getSubject() + ", "
                           + "Expiration:" + payload.getExpiration() + ", "
                           + "IssuedAt:" + payload.getIssuedAt() + ", "
                           + "NotBefore:" + payload.getNotBefore()
     				       + "] ";
		 
		 byte[] digest = contenidoToken.getDigest();
		 int codifIntLlave[] = new int[digest.length];
		 for(int i=0;i<digest.length;i++) {
			 codifIntLlave[i] = Byte.toUnsignedInt(digest[i]);
		 }
		 String strDigest = "Digest(Signature):" + Arrays.toString(codifIntLlave);
				 
		 return strHeader + "\n" + strPayload + "\n" + strDigest;
	}

	public static String extraerCampoString(String tokenFirmado, SecretKey skLlave, String llaveCampo) {
		Jws<Claims> contenido = extraerJwsClaimsTokenFirmado(tokenFirmado, skLlave);
		Claims claims = contenido.getPayload();
		return (String)claims.get(llaveCampo);
	}

	//Lanzara excepcion si el token esta vencido o incorrecto
	public static String extraerUsuarioTokenFirmado(String token, SecretKey skLlave) {
		Jws<Claims> contenido = extraerJwsClaimsTokenFirmado(token, skLlave);
		return contenido.getPayload()
				        .getSubject();
	}
	
	public Date extraerExpiracionTokenFirmado(String token, SecretKey skLlave) {
		Jws<Claims> contenido = extraerJwsClaimsTokenFirmado(token, skLlave);
		return contenido.getPayload()
				        .getExpiration();
	}
	
	//Devuelve el valor del campo, del tipo que sea
	public static <R> R extraerCampo(String tokenFirmado, Function<Claims, R> getterCampo, SecretKey skLlave) {
		Jws<Claims> contenido = extraerJwsClaimsTokenFirmado(tokenFirmado, skLlave);
		Claims claims = contenido.getPayload();
		return getterCampo.apply(claims);
	}

	//Devuelve el valor del campo, del tipo que sea
	public static <R> R extraerCampo(String tokenFirmado, Class<R> tipoJavaCampo, String campo, SecretKey skLlave) {
		@SuppressWarnings("unchecked")
		Function<Claims, R> getterCampo = (claims) -> (R) claims.get(campo);
		return extraerCampo(tokenFirmado, getterCampo, skLlave);
	}
	
	public static boolean tokenFirmadoExpirado(String token, SecretKey skLlave) {
		try {
			extraerJwsClaimsTokenFirmado(token, skLlave);
		}
		catch(ExpiredJwtException ex) {
			return true;
		}
		return false;
	}
	
}
