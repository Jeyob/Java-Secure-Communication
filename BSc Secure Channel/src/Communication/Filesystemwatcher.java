package Communication;

import java.io.File;
import java.io.FileInputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import dkand12.Helpers.trippel;

public class Filesystemwatcher implements Runnable {
	
	private final String directoryPath;
	private ByteBuffer buffer = null, longBuffer = null, intBuffer = null;
	private FileInputStream instream = null;
	private FileChannel filechannel = null;
	private File directory = null;
	private byte[] buf = null;
	private Long serial = 0L;
	private UDP_Client_Writer callback = null;
	
	
	public Filesystemwatcher(UDP_Client_Writer callback, String path, int bufferSize){
		directoryPath = path;
		buffer = ByteBuffer.allocate(bufferSize);
		longBuffer = ByteBuffer.allocate(8); //type Long is 8 byte
		intBuffer = ByteBuffer.allocate(4); //type int is 4 byte
		buf = new byte[bufferSize];
		directory = new File(path);
		
		this.callback = callback;
		
			if(!directory.isDirectory()){
				System.err.println("Path is not a directory");
			}
		}
		
	public void run() {
		
		File[] files = null, files2 = null;
		int nRead, nr;
		byte[] dstBuffer = null;
		serial = System.currentTimeMillis();
		
		while(true) {
		try{
			files = directory.listFiles();
			synchronized (this) {
				Thread.sleep(500);
			}
			
			files2 = directory.listFiles();
			
			files = files.length < files2.length ? files2 : files;
			if(files.length>0)
				System.out.println("Number of files found: "+files.length);
			for(File f : files) {
				serial++;
			//	System.out.println("Serial is "+serial);
				instream = new FileInputStream(f);
				filechannel = instream.getChannel();
			
				nRead = 0;
				nr = 1; //package number (start from 1)
				
				buffer.clear(); //clear previous data
				longBuffer.clear(); 
				intBuffer.clear();
			
			/* All Credit to Dr. David R. Nadeau for this code snippet and excellent performance analysis at: http://nadeausoftware.com/articles/2008/02/java_tip_how_read_files_quickly [accessed: 2012-07-21] */
			
			while((nRead = filechannel.read(buffer)) !=- 1) { 
				if(nRead==0){
					continue;
				}
			//	System.out.println("nRead:"+nRead);
				buffer.position(0);
				buffer.limit(nRead);
				
				dstBuffer = new byte[buffer.remaining()];
				
				buffer.get(dstBuffer);
				
				//System.out.println("bytes retrivied");
				
				callback.push(new trippel<Long, Integer, byte[]>(serial, nr++, dstBuffer)); //packaged data ready for transmission
				
				buffer.clear(); //empty buffer for new data
			}
			synchronized (callback) {
				
				callback.notify();
			}
			
			/*******************************/
			filechannel.close();

			f.delete(); //remove file form directory when finished
		 }
		} catch(Exception e) {
			e.printStackTrace();
		}
		
		synchronized (this) {
			try {
			//	System.out.println("wating");
				wait(5000); 
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
		}
	}
}
