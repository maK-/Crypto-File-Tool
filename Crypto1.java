import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.math.BigInteger;
import java.util.*;
import java.io.*;
import argparser.*;

/*
This tool was designed to complete Assignment1-CA547
The argument parser makes it easier to handle passed command line 
arguments. It provided a level of flexibility with using/testing the 
functionality of my assignment.

I used the argparser library from below
http://www.cs.ubc.ca/~lloyd/java/argparser.html
*/
public class Crypto1{

    public static void main(String[] args){
        //For use with our argument parser class
        StringHolder password = new StringHolder();
        StringHolder encr_file = new StringHolder();
        IntHolder exponent = new IntHolder();
        BooleanHolder public_key = new BooleanHolder();
        BooleanHolder set_aeskey = new BooleanHolder();
        BooleanHolder set_encrypt = new BooleanHolder();
        BooleanHolder set_hex = new BooleanHolder();
        BooleanHolder del_my = new BooleanHolder();

        //Parsing cmd-line arguments
        ArgParser arg = new ArgParser("./run.sh <params>\nCiaran McNally");
        arg.addOption("-p,-password %s #Pass in a password", password);
        arg.addOption("-a, -aeskey %v #Flag to Generate our 256-bit AES key,"+
                        "using command-line defined password and salt", set_aeskey);
        arg.addOption("-e, -encrypt %v #Flag to signify AES encryption of file", set_encrypt);
        arg.addOption("-f, -file %s #File to encrypt with AES", encr_file);
        arg.addOption("-x, -hex %v #converts my.* files to hex equivalent hex.*", set_hex);
        arg.addOption("-d, -delete %v #Delete my.* files after hex conversion.", del_my);
        arg.addOption("-k, -pubkey %v #Saves encrypted password to File, uses \"pubkey\" file.", public_key);
        arg.addOption("-exp, -exponent %d #Define exponent, if not defined uses default of 65537.",exponent);
        arg.matchAllArgs(args);

        //This section parses the flags and various options
        if(set_aeskey.value && password.value != null && set_encrypt.value == false){
            String aeskey = generate_aeskey(password.value);   
            System.out.println("AES Secret key: "+aeskey+"\n");

            if(public_key.value){
                System.out.println("Generating RSA secured Password using \"pubkey\"...");        
                String rsa = rsa_passwd(password.value, exponent.value);
            }
        }
        else if(set_encrypt.value){
            if(encr_file.value == null){
                System.out.println("No file to encrypt specified! Note: use -f <file>");
            }
            else{
                String enc = encrypt_file(encr_file.value);
                System.out.println(enc);
            }
        }
        else if(set_hex.value){
            convertToHex(del_my.value);
        }
        else{
            System.out.println("Ciaran McNally \nNo Flags or arguments provided, use -help\n");
        }
    }
    /*
    This generates our 256-bit AES Secret Key
    It dumps the raw salt data to "my.salt" and the key to "my.aes"
    */
    public static String generate_aeskey(String passwd){
        String s = "my.salt"; //where salt will be stored
        String aes = "my.aes"; //aes key will be stored
        Cryptool tool = new Cryptool();
        FileWizard f = new FileWizard();
        System.out.println("\nGenerating 256-bit AES key...\n");
        RandomBytes random = new RandomBytes(128);
        byte[] SALT = random.get();
        System.out.println("Salt: "+tool.byteToStr(SALT));
        
        //Generate our 256-bit AES secret key.
        byte[] aes_key = tool.SHA256_N(passwd, tool.byteToStr(SALT), 200);
        f.toFile(aes, aes_key);
        f.toFile(s, SALT);
        System.out.println("Salt stored in \"my.salt\"");
        System.out.println("AES secret key stored in \"my.aes\"");
        return tool.byteToStr(aes_key);
    }

    /*
    Encrypts a specified file using a pre-generated aes-key,
    "my.iv" is created containing are random IV.
    File data is also dumped un a raw format to my.encrypted.
    */
    public static String encrypt_file(String file){
        String iv = "my.iv"; // where iv is stored
        String efile = "my.encrypted"; //Encrypted file
        Cryptool tool = new Cryptool();
        FileWizard f = new FileWizard();
        System.out.println("\nEncrypting file: "+file+" ...\n");

        byte[] unenc_file = f.fromFile(file);
        byte[] aes_secretkey = f.fromFile("my.aes");
        byte[] padded_file = tool.padfile(unenc_file);
        byte[] iv_data = null;
        byte[] encrypted_data = null;
        RandomBytes ivgen = new RandomBytes(128);
        iv_data = ivgen.get();
        f.toFile(iv, iv_data);
        System.out.println("IV: "+tool.byteToStr(iv_data));
        System.out.println("IV stored in \"my.iv\"");
        
        try{
            //Encrypting our file
            IvParameterSpec myiv = new IvParameterSpec(iv_data);
            SecretKeySpec mykey = new SecretKeySpec(aes_secretkey, "AES");
            Cipher myaes = Cipher.getInstance("AES/CBC/NoPadding");
            myaes.init(Cipher.ENCRYPT_MODE, mykey, myiv);
            encrypted_data = myaes.doFinal(padded_file);
        }
        catch(Exception e){ 
            System.out.println("Error while encrypting!");
            e.printStackTrace();
        }

        //Store encrypted data to file
        f.toFile(efile, encrypted_data);
        return "File encrypted and stored in \"my.encrypted\"\n";
    }

    /*
    This function converts all raw byte data files to their hexadecimal 
    string equivalents and writes them to respective files.
    */
    public static void convertToHex(Boolean delete){
        String salt = "my.salt";
        String aes = "my.aes";
        String iv = "my.iv"; 
        String efile = "my.encrypted";

        //Files to store data
        byte[] salt_data = null;
        byte[] aes_data = null;
        byte[] iv_data = null;
        byte[] efile_data = null;

        FileWizard f = new FileWizard();
        Cryptool t = new Cryptool();
        System.out.println("\nReading and converting Files...\n");
        salt_data = f.fromFile(salt);
        aes_data = f.fromFile(aes);
        iv_data = f.fromFile(iv);
        efile_data = f.fromFile(efile);

        //Writing hexadecimal representation of files to disk
        f.strToFile("hex.salt", t.byteToStr(salt_data));
        f.strToFile("hex.aes", t.byteToStr(aes_data));
        f.strToFile("hex.iv", t.byteToStr(iv_data));
        f.strToFile("hex.encrypted", t.byteToStr(efile_data));

        if(delete){
            try{
                File s = new File(salt);
                if(s.delete())  System.out.println(salt+" deleted! hex.salt created!");
                File a = new File(aes);
                if(a.delete())  System.out.println(aes+" deleted! hex.aes created!");
                File i = new File(iv);
                if(i.delete())  System.out.println(iv+" deleted! hex.iv created! ");
                File e = new File(efile);
                if(e.delete())  System.out.println(efile+" deleted! hex.encrypted created!");
            }
            catch(Exception ex){
                ex.printStackTrace();
            }
        }        
    }

    /*
    This function takes in a String password and encrypts it
    using RSA. It also takes the exponent(e). The default pubkey 
    or modulus(N) used should be stored in the file "pubkey"
    */
    public static String rsa_passwd(String passwd, int expo){
        String modulus = "";
        if(expo == 0)
            expo = 65537;
        FileWizard f = new FileWizard();
        modulus = f.strFromFile("pubkey");
        System.out.println(modulus);
        Cryptool t = new Cryptool();
        //Password into byte array
        byte[] pass = passwd.getBytes();
       
        //Read in our hex String to an int
        BigInteger n = new BigInteger(modulus,16);
        BigInteger e = new BigInteger(Integer.toString(expo));
        BigInteger p = new BigInteger(t.byteToStr(pass), 16);
        System.out.println("\nExponent used: "+expo);
        System.out.println("Password: "+passwd);
        System.out.println("Password as hex: "+p.toString(16));
        System.out.println("Solving p^e (mod n) ...");
        BigInteger result = modularExpo(p,e,n);
        System.out.println("\nPassword as hex: "+result.toString(16));
        f.strToFile("rsa.password", result.toString(16));
        System.out.println("\nPassword saved to file \"rsa.password\"!\n");
        
        return "rsa";
    }

    /*
    This manually calculates the modular exponentiation of our RSA data
    I found some very useful pseudocode at the following location,
    it uses right to left binary method

    This greatly helped my understanding of the algorithm.
    http://en.wikipedia.org/w/index.php?title=Modular_exponentiation
    */
    
    public static BigInteger modularExpo(BigInteger p, BigInteger e, BigInteger n){
        BigInteger result = new BigInteger("1");
        BigInteger zero = new BigInteger("0");
        if(e.compareTo(zero)==-1) e.negate();
        while(!e.equals(zero)){
            if(e.mod(new BigInteger("2")).equals(new BigInteger("1"))){
                //result = (result*p)mod n
                BigInteger x = result.multiply(p);
                result = x.mod(n);
            }
            e = e.shiftRight(1);
            //p = (p*p)mod n
            BigInteger y = p.multiply(p);
            p = y.mod(n);
        }
        return result;
    }
}


/*
This class is used for doing multiple things with byte arrays

Returns the following:
-hexadecimal Strings of byte array
-SHA-256 hash of String as byte array
-SHA-256 on password & salt pair N-times
-joint array from 2 byte arrays
-padding of byte array
*/
class Cryptool{
    /*
    Generate hashed byte array from input string.
    MessageDigest -> performs hashing of byte array
    */
    public byte[] SHA256_Gen(byte[] input){
        try{
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(input);
            return hash;
        }
        catch(Exception e){
            throw new RuntimeException(e);
        }
    }

    /*
    This performs N-hashes on provided password & salt Strings
    */
    public byte[] SHA256_N(String p, String s, int n){
        String joint = p + s;
        byte[] concat = null;
        try{
            concat = joint.getBytes("UTF-8");
        }
        catch(Exception e){
            throw new RuntimeException(e);
        }
        for(int i=0; i < n; i++){
            concat = SHA256_Gen(concat);
        }
        return concat;
    }

    /*
    Convert byte array to hexadecimal String
    StringBuilder -> This was very useful for keeping the bytes in
    order while also allowing the easy building of a String.
    */
    public String byteToStr(byte[] b){
        StringBuilder hexbuffer = new StringBuilder();
        for (int i=0; i<b.length; i++){
            String hex = Integer.toHexString(0xff & b[i]);
            if(hex.length() == 1){
                hexbuffer.append("0");
            }
            hexbuffer.append(hex);
        }
        return hexbuffer.toString();   
    }

    /*
    This joins the first byte array to the second and returns
    the combination of the two
    */
    public byte[] join(byte[] one, byte[] two){
        byte[] concat = new byte[one.length + two.length];
        System.arraycopy(one, 0, concat, 0, one.length);
        System.arraycopy(two, 0, concat, one.length, two.length);
        return concat;
    }
    
    /*
    This function is used to pad a byte array in the specified
    way. As we are using a 128bit block, we need to find the offset
    of the current file and pad it out with 1000 0000 0000...
    
    Looking up an ascii table I discovered the '@' character is
    equal to 1000 0000 in bits. This allows me to pad a single bit
    and then insert nulls in the remaining byte spaces.
    */
    public byte[] padfile(byte[] file){
        String nullchar = "\0"; //Ascii of 0000 0000
        String binary_1 = "@";  //Ascii of 1000 0000
        int offset = file.length % 16; //bytes over 128-bit block
        int diff = 16 - offset; //bytes we need to fill/write
        StringBuilder full_block = null;
        StringBuilder remain_block = null;

        //Exactly 128bit block = create additional full block
        if(offset == 0){
            full_block = new StringBuilder();
            full_block.append(binary_1);
            for(int i=0; i<15; i++)
                full_block.append(nullchar);
        }
        else{   //Not exactly matched, fill remaining block
            remain_block = new StringBuilder();
            for(int i=0; i<diff; i++){
                if(i==0)    remain_block.append(binary_1);
                else    remain_block.append(nullchar);
            }
        }
        byte[] pad = null;
        try{
            if(full_block != null){
                String full = full_block.toString();
                pad = full.getBytes("UTF-8");
            }
            else{
                String remain = remain_block.toString();
                pad = remain.getBytes("UTF-8");
            }
        }
        catch(Exception e){
            throw new RuntimeException(e);
        }
        
        //Join file with pad and return.
        byte[] ufile = join(file, pad);
        return ufile;
    }

    /*
    This converts a hex String to a byte array
    */
    public byte[] hexStrToByte(String data){
        int sizeOfArr = data.length()/2;
        int position = 0;
        byte[] data_b = new byte[sizeOfArr];
        for(int i=0; i<data_b.length; i++){
            position = i*2;
            String bytes = data.substring(position, position+2);
            byte x = (byte)(Integer.parseInt(bytes, 16) & 0xff);
            data_b[i] = x;
        }
        return data_b; 
    }

}


/*
This class is used to securely generate a random number of N-bit size
*/
class RandomBytes{
    private int bitsize;

    RandomBytes(int b){
        bitsize = b;
    }

    /*
    This generates a byte array containing our random key
    of N-bit length. This is a cryptographically secure
    random number.

    KeyGenerator -> used to generate keys for symmetric algorithms
    */
    public byte[] get(){
        try{
            SecureRandom random = new SecureRandom();
            KeyGenerator keygen = KeyGenerator.getInstance("AES");
            keygen.init(bitsize, random);
            Key key = keygen.generateKey();
            return key.getEncoded();
        }
        catch(Exception e){
            throw new RuntimeException(e);
        }
    }
}

/*
This class is used to read and write byte data to and from files
*/
class FileWizard{
    
    //write byte data to a file
    public void toFile(String filename, byte[] outdata){
        try{
            File file = new File(filename);
            FileOutputStream data = new FileOutputStream(file);
            data.write(outdata);
            data.close();
        }
        catch(FileNotFoundException e){
            System.out.println("\nFile not found!");
        }   
        catch(IOException e){
            System.out.println("\nIO Error!");
        }
    }
    //read bytes data from file
    public byte[] fromFile(String filename){
        byte[] file_data = null;
        try{
            File file = new File(filename);
            FileInputStream data = new FileInputStream(file);
            file_data = new byte[(int)file.length()];
            data.read(file_data);
            data.close();
            return file_data;
        }
        catch(FileNotFoundException e){
            System.out.println("\nFile not found!");
        }
        catch(IOException e){
            System.out.println("\nIO Error!");
        }
        return file_data;
    }

    //write string data to a file
    public void strToFile(String filename, String data){
        File file = new File(filename);
        try{
            FileWriter dataf = new FileWriter(file);
            dataf.write(data);
            dataf.close();
        }
        catch(FileNotFoundException e){
            System.out.println("\nFile not found!");
        }
        catch(IOException e){
            System.out.println("\nIO Error!");
        }
    }

    //Reads string from a file
    public String strFromFile(String filename){
        String mydata = "";
        File file = new File(filename);
        try{
            Scanner data = new Scanner(file);
            mydata = data.nextLine();
            data.close();
        }
        catch(FileNotFoundException e){
            System.out.println("\nFile not found!");
        }
        return mydata;
    }
}
