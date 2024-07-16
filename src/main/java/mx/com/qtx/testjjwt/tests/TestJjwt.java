package mx.com.qtx.testjjwt.tests;

//import java.nio.charset.Charset;
import java.util.Arrays;

import javax.crypto.SecretKey;

import io.jsonwebtoken.io.Encoders;
import mx.com.qtx.testjjwt.AlgoritmoCifradoLlaveSimetrico;
import mx.com.qtx.testjjwt.TokensJwtUtil;

public class TestJjwt {

	public static void main(String[] args) {
//		test_GeneracionLlave();
		test_CreacionTokenJWT();
		
	}
	
	private static void test_GeneracionLlave() {
		System.out.println("*** test_GeneracionLlaves() ***");
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
		System.out.println("*** test_CreacionTokenJWT() ***");
		String token = TokensJwtUtil.generarToken("alex");
		System.out.println("Token:" + token);		
	}

}
