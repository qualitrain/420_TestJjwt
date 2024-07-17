package mx.com.qtx.testjjwt.tests;

//import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;

import io.jsonwebtoken.io.Encoders;
import mx.com.qtx.testjjwt.AlgoritmoCifradoLlaveSimetrico;
import mx.com.qtx.testjjwt.TokensJwtUtil;

public class TestJjwt {

	public static void main(String[] args) {
//		test_GeneracionLlave();
		
//		test_CreacionTokenJWT();
		
//		test_CreacionTokenJWTconClaimsPersonalizados();
		
		test_ParserTokenFirmado();
		test_ExtraerDatos();
		test_tokenExpirado();
	}
	
	private static void test_GeneracionLlave() {
		System.out.println("\n*** test_GeneracionLlaves() ***");
		for(AlgoritmoCifradoLlaveSimetrico algoI:AlgoritmoCifradoLlaveSimetrico.values() ) {
			
			SecretKey llave = TokensJwtUtil.generarLlave(algoI);
			
			System.out.println("==============================================================");
			System.out.println("Llave generada");
			System.out.println("Algoritmo:" + llave.getAlgorithm());
			System.out.println("Formato:" + llave.getFormat());
			
			byte[] codificacionLlave = llave.getEncoded();
			
			System.out.println("Encoded:(tamano en bytes): " + codificacionLlave.length);
			
	//		System.out.println("Encoded:(como String): " + new String(codificacionLlave, Charset.forName("UTF-8")));
			
			System.out.println("Encoded:(como Arreglo): " + Arrays.toString(codificacionLlave));
			
			int codifIntLlave[] = new int[codificacionLlave.length];
			for(int i=0;i<codificacionLlave.length;i++) {
				codifIntLlave[i] = Byte.toUnsignedInt(codificacionLlave[i]);
			}
			System.out.println("Encoded:(como Arreglo unsigned): " + Arrays.toString(codifIntLlave));
			
			String codifBase64 = Encoders.BASE64.encode(codificacionLlave);
			System.out.println("Encoded:(base 64): " + codifBase64);
		}
		
	}
	
	private static void test_CreacionTokenJWT(){
		System.out.println("\n*** test_CreacionTokenJWT() ***");
		String token = TokensJwtUtil.generarToken("alex");
		System.out.println("Token:" + token);		
	}
	
	private static String test_CreacionTokenJWTconClaimsPersonalizados(){
		System.out.println("\n*** test_CreacionTokenJWTconMap() ***");
		Map<String,Object> mapClaims = new HashMap<>();
		mapClaims.put("rol","Agente");
		mapClaims.put("permisos", "0777");
		String token = TokensJwtUtil.generarToken("beto",mapClaims);
		System.out.println("Token:" + token);
		return token;
	}
	
	private static void test_ParserTokenFirmado() {
		System.out.println("\n*** test_ParserTokenFirmado() ***");
		
		SecretKey llave = TokensJwtUtil.generarLlave(AlgoritmoCifradoLlaveSimetrico.HmacSHA512);
		
		Map<String,Object> mapClaims = new HashMap<>();
		mapClaims.put("rol","Administrador");
		mapClaims.put("permisos", "0777");
		String token = TokensJwtUtil.generarToken("mortadelo", mapClaims, llave);
		
		String resultado = TokensJwtUtil.extraerContenidoTokenFirmadoStr(token, llave);
		System.out.println(resultado);
		
		String rol = TokensJwtUtil.extraerCampoString(token, llave, "rol");
		System.out.println("Rol recuperado del token:" + rol);
	}

	private static void test_ExtraerDatos() {
		System.out.println("\n*** test_ExtraerDatos() ***");
		
		SecretKey llave = TokensJwtUtil.generarLlave(AlgoritmoCifradoLlaveSimetrico.HmacSHA512);
		
		Map<String,Object> mapClaims = new HashMap<>();
		mapClaims.put("rol","Administrador");
		mapClaims.put("permisos", "0777");
		String token = TokensJwtUtil.generarToken("mortadelo", mapClaims, llave);
		
		String usuario =  TokensJwtUtil.extraerUsuarioTokenFirmado(token,llave);
		String rol =      TokensJwtUtil.extraerCampo(token, claims -> (String)claims.get("rol"), llave );
		String permisos = TokensJwtUtil.extraerCampo(token, claims -> (String)claims.get("permisos"), llave  );
		System.out.println("Usuario:" + usuario);
		System.out.println("Rol:" + rol);
		System.out.println("Permisos:" + permisos);
		
		System.out.println("\n..con otra función...");
		
		rol =      TokensJwtUtil.extraerCampo(token, String.class , "rol" , llave );
		permisos = TokensJwtUtil.extraerCampo(token, "permisos".getClass(),"permisos", llave  );
		System.out.println("Rol:" + rol);
		System.out.println("Permisos:" + permisos);

	}
	
	private static void test_tokenExpirado() {
		System.out.println("\n*** test_tokenExpirado() ***");
		
		SecretKey llave = TokensJwtUtil.generarLlave(AlgoritmoCifradoLlaveSimetrico.HmacSHA512);
		
		Map<String,Object> mapClaims = new HashMap<>();
		mapClaims.put("rol","Administrador");
		mapClaims.put("permisos", "0777");
		String tokenOk = TokensJwtUtil.generarToken("mortadelo", mapClaims, llave);
		String tokenExpirado = TokensJwtUtil.generarToken("filemon", mapClaims, llave, -100);
		
		if(TokensJwtUtil.tokenFirmadoExpirado(tokenExpirado, llave)) {
			System.out.println("El token de filemon está expirado");
		}
		else {
			String usuario = TokensJwtUtil.extraerUsuarioTokenFirmado(tokenExpirado,llave);
			System.out.println("Todo ok con el token de " + usuario);
		}
		
		if(TokensJwtUtil.tokenFirmadoExpirado(tokenOk, llave)) {
			System.out.println("El token de mortadelo está expirado");
		}
		else {
			String usuario = TokensJwtUtil.extraerUsuarioTokenFirmado(tokenOk,llave);
			System.out.println("todo ok con el token de " + usuario);
		}
		
	}	
}
