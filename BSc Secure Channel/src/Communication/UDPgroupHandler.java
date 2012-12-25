package Communication;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.ListIterator;

public class UDPgroupHandler implements Runnable {

	List<byte[]> packages = null;
	
	private long starttime = 0;
	private long elapsed = 0;
	private long serial = 0;

	//private final static long MINUTE = 60000;
	//private final static long HALF_MINUTE = 30000;
	private final long TEN_SECONDS = 10000;
	
	private UDPdataQueue caller;
	
	private boolean keepworking = true;
	
	//constructor
	public UDPgroupHandler(long serial, int nr, byte[] firstdata, UDPdataQueue caller){
		
		packages = new ArrayList<byte[]>();
		packages.add(firstdata);
		this.caller = caller;
		this.serial = serial;
	
	}
	
	public synchronized void addData(int nr, byte[] data) {
		packages.add(data);
		starttime = System.currentTimeMillis(); //update elapsedtime
		}
	
	private void saveToDisk() {
		FileOutputStream fos = null;
		BufferedOutputStream bos = null;
		
		synchronized (this) {
			
		try {
			
			fos = new FileOutputStream(new File("RECEVIED_UDP_DATA\\TASKGROUP_"+serial));
			bos = new BufferedOutputStream(fos);

			
			for(ListIterator<byte[]> iterator = packages.listIterator();iterator.hasNext();){
				bos.write(iterator.next());
			}
			
			bos.close();
			
		} catch(Exception e){
			e.printStackTrace();
		}
	}
}
	
	@Override
	public void run() {
		 starttime = System.currentTimeMillis();
		 elapsed = 0;
		
		while(keepworking) {
				elapsed = (System.currentTimeMillis() - starttime);
				
				if(elapsed > TEN_SECONDS){
					saveToDisk();
					caller.finished(serial); //remove entry from parent table 
					keepworking = false; //this thread should end now
				}
				
				synchronized (this) { //LOCK class
					try {
						wait(1000); //catch your breath for a second...
					}catch (InterruptedException e) {
						e.printStackTrace();
					}
				}
			}
		}
	
	public static void main(String args[]) {
		//UDPdatagrampacket p1 = new UDPdatagrampacket(1000, new pair<Integer, Integer>(1, 3), "Jonas".getBytes());
		
		//UDPdataQueue q = new UDPdataQueue();
		//q.push(p1);
		//q.run();
		//		Thread t = new Thread(q);
//		t.start();
		
		
	}
}

