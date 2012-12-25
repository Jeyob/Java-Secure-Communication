//package dkand12.KeyManager;
//
//import java.io.File;
//import java.io.FileInputStream;
//import java.io.FileNotFoundException;
//import java.io.FileOutputStream;
//import java.io.IOException;
//import java.io.ObjectInputStream;
//import java.io.ObjectOutputStream;
//import java.io.Serializable;
//import java.util.HashMap;
//
//public class UserRegistry implements Serializable{
//	/**
//	 * 
//	 */
//	public static void main(String args[]){
//		
//	}
//	
//	
////	private static final long serialVersionUID = 1161189429566230655L;
////	
////	private FileInputStream in = null;
////	private FileOutputStream out = null;
////	private ObjectInputStream objIn = null;
////	private ObjectOutputStream objOut = null;
////	
////	private HashMap<String, Certificate> registry = null;
////	
////	
////	public UserRegistry(String filename){ //exception is raised if file is not found		
////		this(filename, false);
////	}
////	
////	public UserRegistry(String filename, boolean createNew){ //if file is not found create new?
////		try {
////			
////			in = new FileInputStream(filename);
////			objIn = new ObjectInputStream(in);
////			
////			registry = (HashMap<String, Certificate>)objIn.readObject();
////		
////			objIn.close();
////			in.close();
////			
////		}catch(FileNotFoundException e){
////			
////			System.err.println("File not found");
////			
////			if(createNew)
////				new File(filename);
////			
////			System.exit(0);
////			
////		} catch (IOException e) {
////			e.printStackTrace();
////		} catch (ClassNotFoundException e) {
////			e.printStackTrace();
////		}
////		
////		
////		registry = new HashMap<String, Certificate>();
////		
////		
////	}
////	
////	@Override
////	protected void finalize() throws Throwable {
////	
////		try {
////			
////		}catch(IOException e){
////			
////		}finally {
////		// TODO Auto-generated method stub
////		super.finalize();
////	} 	
////	}
////	
//	
//}
