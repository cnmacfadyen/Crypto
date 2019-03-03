import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Scanner;

import FormatIO.Console;

public class KPTdraft {
	public static void main(String[] args) {
		int max = 65536;  //max value of key - a 16-bit hex number
		FileReader fr = null;
		BufferedReader br = null;
		int key = 0;//16-bit hex number
		int ctArraySize = 0; //size of the ciphertext hex numbers array
		String plaintextHex = "0x4368"; 
		String ciphertextHex = ""; //need to read in from a file
		String[] ciphertextArray = new String[101]; //array of strings to hold each line of the ciphertext file (there are 101 lines)
		int[] ciphertextInts = new int[101]; 
		int[] possibleKeys = new int[101];
		int foundKey = 0;
		int plaintextInt = Hex16.convert(plaintextHex);
		int decryptedTextInt = 0;
		int fullDecryptedMessage = 0;

////////////////////////////// FILE READING ////////////////////////////////////	
		
		// read the hex values in from the first ciphertext file
		
		try {
			fr = new FileReader("ct1.txt");
			Scanner s = new Scanner(fr);
			br = new BufferedReader(fr);		
			
			while(s.hasNextLine()) {
				String line = s.nextLine();
				String [] tokens = line.split("\n");
				ciphertextHex = tokens[0];
				ciphertextArray[ctArraySize++] = ciphertextHex;			
			}
		}catch(FileNotFoundException e) {
			e.printStackTrace();
		}catch (IOException e) {
			e.printStackTrace();
		}finally {
			if(fr != null) {
				try {
					fr.close();
					br.close();
				}catch(IOException e){
					e.printStackTrace();
				}
			}
		}
		
////////////////////////////// END OF FILE READING ////////////////////////////////////
		
		// convert each ciphertext hexadecimal to an int 
		
		for(int i=0;i<ciphertextArray.length;i++) { 
			ciphertextInts[i] = Hex16.convert(ciphertextArray[i]);
		}
	
		// Loop over the array of ciphertext integers to find the key 
		// do this for CTO one?
		
//		for(int i=0;i<ciphertextInts.length;i++) {
			for(key=0;key<=max;key++) { // loop over all possible values of key, incrementing by one each time
				decryptedTextInt = Coder.decrypt(key, ciphertextInts[0]); // decrypt the first line of the ciphertext using each possible key value 
				if(decryptedTextInt == plaintextInt) { // if the decrypted ciphertext matches the plaintext
					System.out.println("run: " + 0 + ", decrypted text: " + decryptedTextInt + ", key: " + key);
					foundKey = key;
				}
			}
//		}
		
			
		//use for CTO one??
		for(int i=0;i<possibleKeys.length;i++) {
//			System.out.println(possibleKeys[i]);
		}
		
		for(int i=0;i<ciphertextInts.length;i++) {
			fullDecryptedMessage = Coder.decrypt(foundKey, ciphertextInts[i]);
			
			System.out.println(fullDecryptedMessage);
		}
		
	}
}
