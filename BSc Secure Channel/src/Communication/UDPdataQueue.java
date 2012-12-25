package Communication;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;

public class UDPdataQueue implements Runnable {

	private ConcurrentLinkedQueue<UDPdatagrampacket>  UDPpacketqueue = null;
	private HashMap<Long, UDPgroupHandler> activeUDPgroups = null;
	private Set<Long> finishedSerials = null;
	
	public UDPdataQueue(){
		this.UDPpacketqueue = new ConcurrentLinkedQueue<UDPdatagrampacket>(); 
		this.activeUDPgroups = new HashMap<Long, UDPgroupHandler>();
		this.finishedSerials = new HashSet<Long>();
	}
	
	public synchronized void push(UDPdatagrampacket data){
		this.UDPpacketqueue.add(data);
	}
	
	public synchronized UDPdatagrampacket pop() {
		return UDPpacketqueue.poll();
	}

	public synchronized void finished(long serial){
		System.out.println("[" + serial + "] finished download"  );
		activeUDPgroups.remove(serial);
		finishedSerials.add(serial);
		
	}
	
	@Override
	public void run() {
		
		while(true) { /* this version uses a single thread to iterate over the list */
				
			try{
				for(UDPdatagrampacket entry = pop(); entry!=null; entry = pop()){
				
					if(activeUDPgroups.containsKey(entry.getGroupserial())){
				
						activeUDPgroups.get(entry.getGroupserial()).addData(entry.getNr(), entry.getData());
				
				} else if(finishedSerials.contains(entry.getGroupserial())) {
					//for now simply drop the package
				} else{
					//create new entry
						UDPgroupHandler handler = new UDPgroupHandler(entry.getGroupserial(),entry.getNr(),entry.getData(),this);
						activeUDPgroups.put(entry.getGroupserial(), handler);
						new Thread(handler).start(); //start thread
						System.out.println(String.format("%d unique entrys", UDPpacketqueue.size()));
					}
				}
//				synchronized (this) {
//					wait(1000); //yield
//				}
				
		}catch(Exception e){
			e.printStackTrace();
		}
			/* if we come here the queue is currently empty, put thread to sleep */

			synchronized (this) {	
				try {
					this.wait(5000);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}
		}
	}
}

