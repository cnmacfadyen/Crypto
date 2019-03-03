import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;
import java.util.Scanner;

import FormatIO.EofX;

public class CTO {
	private static FileReader fr = null;
	private static FileWriter fw = null;
	private static BufferedReader br = null;
	private static int[] fullMessageInts;
	private static int numLines = 31; //number of lines in the ciphertext file
	private static String ctFile = "ct2.txt";
	private static String outputFile = "ct2_h.txt";
	
	public static void main(String[] args) {
		String[] ctArray = readCipherFile(ctFile);
		int[] ctInts = convertCipherHexToInts(ctArray);
		String[] hexMessage = new String[numLines]; //decrypt the first five lines
		for(int i=0;i<65536;i++) {
			fullMessageInts = decryptFullMessage(ctInts, i);
			hexMessage = convertMessageIntsToHex();
			writePossibleMessageToFile(hexMessage);
		}
	}
	
	public static void writePossibleMessageToFile(String[] possibleHexMessage) {
		try {
			fw = new FileWriter(outputFile, true);
			for(int i=0;i<possibleHexMessage.length;i++) {
				fw.write(possibleHexMessage[i]);
				fw.write("\n");	
			}
		}catch(IOException e) {
			e.printStackTrace();
		}finally {
			if(fw!=null) {
				try {
					fw.close();  //close the file
				}catch(IOException e) {
					e.printStackTrace();
				}
			}
		}
	}
	
	// read the hex values in from the first ciphertext file
	public static String[] readCipherFile(String filepath) {
		String ciphertextHex = ""; //need to read it in from a file
		String[] ciphertextArray = new String[numLines]; //array of strings to hold each line of the ciphertext file (there are 31 lines)
		int ctArraySize = 0; //size of the ciphertext hex numbers array
		
		try {
			fr = new FileReader(filepath);
			Scanner s = new Scanner(fr);
			br = new BufferedReader(fr);		
			
			while(s.hasNextLine()) {
				String line = s.nextLine();
				String [] tokens = line.split("\n"); //read in line by line
				ciphertextHex = tokens[0];
				ciphertextArray[ctArraySize++] = ciphertextHex; //add each line to the next index of the ciphertext String array			
			}
		}catch(FileNotFoundException e) {
			e.printStackTrace();
		}finally {
			if(fw != null) {
				try {
					fw.close();
				}catch(IOException e){
					e.printStackTrace();
				}
			}
		}
		return ciphertextArray; //returns an array of Strings containing each line of the hexadecimal ciphertext file in order
	}
	
	// convert each line of hexadecimal ciphertext to an int 
	public static int[] convertCipherHexToInts(String[] hexArray) {
		int[] ciphertextInts = new int[numLines];
		
		for(int i=0;i<hexArray.length;i++) { 
			ciphertextInts[i] = Hex16.convert(hexArray[i]);
		}
		return ciphertextInts;
	}
	
	// find the encryption key by performing a brute force exhaustive search of the keyspace
	public static int[] findPossibleKeys(int[] ciphertextInts, int plaintext) {
		int key = 0;
		int max = 65536;  //max value of key - a 16-bit hex number
		int[] possibleKeys = new int[ciphertextInts.length];
		int foundKey = 0;
		int decryptedTextInt[] = new int[ciphertextInts.length];
		
		for(int i=0;i<ciphertextInts.length;i++) {
			for(key=0;key<=max;key++) { // loop over all possible values of key, incrementing by one each time
				decryptedTextInt[i] = Coder.decrypt(key, ciphertextInts[i]); 
				if(decryptedTextInt[i] == plaintext) { // if the decrypted ciphertext matches either plaintext
					possibleKeys[i] = key;
				}
			}
		}
		return possibleKeys;
	}
	
	public static void printPossibleKeys(int[] possibleKeys) {
		for(int i=0;i<possibleKeys.length;i++) {
			System.out.println(possibleKeys[i]);
		}
	}
	
	
	// decrypt the rest of the message (into ints) using the found key
	public static int[] decryptFullMessage(int[] ciphertextInts, int key) {
		int[] fullDecryptedMessage = new int[ciphertextInts.length];	
		for(int i=0;i<ciphertextInts.length;i++) {
			fullDecryptedMessage[i] = Coder.decrypt(key, ciphertextInts[i]);		
		}
		return fullDecryptedMessage; 
	}
	
	//convert the full decrypted message from an array of integers into an array of hex numbers to use block2text
	public static String[] convertMessageIntsToHex() {
		String[] fullMessageAsHex = new String[fullMessageInts.length];
		for(int i=0;i<fullMessageInts.length;i++) {
			//fullMessageAsHex[i] = Integer.toHexString(fullMessageInts[i]);
			fullMessageAsHex[i] = String.format("0x%04x", fullMessageInts[i]);
//			if(fullMessageAsHex[i].length() == 5) {
//				fullMessageAsHex[i] = fullMessageAsHex[i] + "0";
//			}else if(fullMessageAsHex[i].length() == 4) {
//				fullMessageAsHex[i] = fullMessageAsHex[i] + "00";
//			}else if(fullMessageAsHex[i].length() == 3) {
//				fullMessageAsHex[i] = fullMessageAsHex[i] + "000";
//			}
		}
		return fullMessageAsHex;
	}
	
//	private static FileReader fr = null;
//	private static FileWriter fw = null;
//	private static BufferedReader br = null;
//	private static int minNumberOfBlocks = 5;
////	private static String plaintextHex = "0x4368"; //
////	private static int plaintextInt = Hex16.convert(plaintextHex);
//	private static int[] fullMessageInts;
//	static String[] hexMessage = new String[minNumberOfBlocks]; 
//
//	
//	public static void main(String[] args) {
//		String[] ctArray = readCipherFile("ct2.txt");
//		int[] ctInts = convertCipherHexToInts(ctArray);
//		int[] possibleKeys = findKey(ctInts);
//
//
//		for(int i=0;i<possibleKeys.length;i++) {
//			fullMessageInts = decryptFullMessage(ctInts, possibleKeys[i]);
//			hexMessage = convertMessageIntsToHex(); 
////			System.out.println("Key: " + possibleKeys[i] + " - Message: " + Arrays.toString(fullMessageInts) + " Hex message: " + Arrays.toString(hexMessage));
//			
//		}
//		
//		for (;;) {
//			int	j = Hex16.convert(hexMessage[0]);
//			int	c0 = j / 256;
//			int	c1 = j % 256;
//			System.out.println((char)c0);
//			if (c1 != 0)
//				System.out.println((char)c1);
//		}
//	}
//	
//	
//	
//	// read the hex values in from the first ciphertext file
//	public static String[] readCipherFile(String filepath) {
//		String ciphertextHex = ""; //need to read it in from a file
//		String[] ciphertextArray = new String[31]; //array of strings to hold each line of the ciphertext file (there are 101 lines)
//		int ctArraySize = 0; //size of the ciphertext hex numbers array
//		
//		try {
//			fr = new FileReader(filepath);
//			Scanner s = new Scanner(fr);
//			br = new BufferedReader(fr);		
//			
//			while(s.hasNextLine()) {
//				String line = s.nextLine();
//				String [] tokens = line.split("\n"); //read in line by line
//				ciphertextHex = tokens[0];
//				ciphertextArray[ctArraySize++] = ciphertextHex; //add each line to the next index of the ciphertext String array			
//			}
//		}catch(FileNotFoundException e) {
//			e.printStackTrace();
//		}finally {
//			if(fw != null) {
//				try {
//					fw.close();
//				}catch(IOException e){
//					e.printStackTrace();
//				}
//			}
//		}
//		return ciphertextArray; //returns an array of Strings containing each line of the hexadecimal ciphertext file in order
//	}
//	
//	// convert each line of hexadecimal ciphertext to an int 
//	public static int[] convertCipherHexToInts(String[] hexArray) {
//		int[] ciphertextInts = new int[minNumberOfBlocks]; //how many blocks do we need to make sure it has been deciphered?
//		
//		for(int i=0;i<5;i++) { 
//			ciphertextInts[i] = Hex16.convert(hexArray[i]);
//		}
//		return ciphertextInts;
//	}
//	
//	// find the encryption key by performing a brute force exhaustive search of the keyspace
//	public static int[] findKey(int[] ciphertextInts) {
//		int max = 65536;  //max value of key - a 16-bit hex number
//		int[] foundKey = new int[max];
//		int decryptedTextInt1 = 0;
//		int decryptedTextInt2 = 0;
//		int decryptedTextInt3 = 0;
//		int decryptedTextInt4 = 0;
//		int decryptedTextInt5 = 0;
//		
//		for(int i=0;i<max;i++) { // loop over all possible values of key, incrementing by one each time
//			decryptedTextInt1 = Coder.decrypt(i, ciphertextInts[0]); // decrypt the first line of the ciphertext using each possible key value 
//			decryptedTextInt2 = Coder.decrypt(i, ciphertextInts[1]);
//			decryptedTextInt3 = Coder.decrypt(i, ciphertextInts[2]);
//			decryptedTextInt4 = Coder.decrypt(i, ciphertextInts[3]);
//			decryptedTextInt5 = Coder.decrypt(i, ciphertextInts[4]);
////			if(decryptedTextInt == plaintextInt) { // if the decrypted ciphertext matches the plaintext
//				foundKey[i] = i;
////			}
//		}
//		return foundKey;
//	}
//	
//	// decrypt the rest of the message (into ints) using the found key
//	public static int[] decryptFullMessage(int[] ciphertextInts, int key) {
//		int[] fullDecryptedMessage = new int[ciphertextInts.length];	
//		for(int i=0;i<minNumberOfBlocks;i++) { //decrypt the minimum number of blocks
//			fullDecryptedMessage[i] = Coder.decrypt(key, ciphertextInts[i]);								
//		}
//		return fullDecryptedMessage; 
//	}
//	
//	//convert the full decrypted message from an array of integers into an array of hex numbers to use block2text
//	public static String[] convertMessageIntsToHex() {
//		String[] fullMessageAsHex = new String[fullMessageInts.length];
//		for(int i=0;i<fullMessageInts.length;i++) {
//			fullMessageAsHex[i] = Integer.toHexString(fullMessageInts[i]);
//			fullMessageAsHex[i] = "0x" + fullMessageAsHex[i];
//		}
//		return fullMessageAsHex;
//	}
}
