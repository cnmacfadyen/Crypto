import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Arrays;
import java.util.Scanner;

public class KPT {
	private static FileReader fr = null;
	private static FileWriter fw = null;
	private static BufferedReader br = null;
	private static String plaintextHex = "0x4368"; // plaintext "Ch" as a hex number
	private static int plaintextInt = Hex16.convert(plaintextHex);
	private static int[] fullMessageInts;
	private static int numLines = 101; //number of lines in the ciphertext file
	private static String ctFile = "ct1.txt";
	private static String outputFile = "ct1_h.txt";
	
	public static void main(String[] args) {
		String[] ctArray = readCipherFile(ctFile);
		int[] ctInts = convertCipherHexToInts(ctArray);
		int encryptionKey = findKey(ctInts);
		fullMessageInts = decryptFullMessage(ctInts, encryptionKey);
		String[] hexMessage = convertMessageIntsToHex(); 
		System.out.println("Key Found: " + encryptionKey);
		try {
			fw = new FileWriter(outputFile);
			for(int i=0;i<hexMessage.length;i++) {
				fw.write(hexMessage[i]);
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
		String[] ciphertextArray = new String[numLines]; //array of strings to hold each line of the ciphertext file (there are 101 lines)
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
	public static int findKey(int[] ciphertextInts) {
		int key = 0;
		int max = 65536;  //max value of key - a 16-bit hex number
		int foundKey = 0;
		int decryptedTextInt = 0;
		
		for(key=0;key<=max;key++) { // loop over all possible values of key, incrementing by one each time
			decryptedTextInt = Coder.decrypt(key, ciphertextInts[0]); // decrypt the first line of the ciphertext using each possible key value 
			if(decryptedTextInt == plaintextInt) { // if the decrypted ciphertext matches the plaintext
				foundKey = key;
			}
		}
		return foundKey;
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
			fullMessageAsHex[i] = String.format("0x%04x", fullMessageInts[i]);
		}
		return fullMessageAsHex;
	}
	
}
