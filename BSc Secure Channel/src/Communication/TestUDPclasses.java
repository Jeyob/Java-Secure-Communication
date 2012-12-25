//package Communication;
//
//import dkand12.Helpers.pair;
//
//public class TestUDPclasses {
//
//	public static void main(String args[]) {
//		
//		UDPdatagrampacket p1 = new UDPdatagrampacket(1000, new pair<Integer, Integer>(1, 3), "Jonas".getBytes());
//		UDPdatagrampacket p2 = new UDPdatagrampacket(1000, new pair<Integer, Integer>(2, 3), "Eyob".getBytes());
//		UDPdatagrampacket p3 = new UDPdatagrampacket(1000, new pair<Integer, Integer>(3, 3), "DONE".getBytes());
//		
//		UDPdatagrampacket _p1 = new UDPdatagrampacket(1001, new pair<Integer, Integer>(1, 3), "Jonas".getBytes());
//		UDPdatagrampacket _p2 = new UDPdatagrampacket(1001, new pair<Integer, Integer>(2, 3), "Eyob".getBytes());
//		UDPdatagrampacket _p3 = new UDPdatagrampacket(1001, new pair<Integer, Integer>(3, 3), "DONE".getBytes());
//
//		UDPdatagrampacket p1_ = new UDPdatagrampacket(1002, new pair<Integer, Integer>(1, 3), "Jonas".getBytes());
//		UDPdatagrampacket p2_ = new UDPdatagrampacket(1002, new pair<Integer, Integer>(2, 3), "Eyob".getBytes());
//		UDPdatagrampacket p3_ = new UDPdatagrampacket(1002, new pair<Integer, Integer>(3, 3), "DONE".getBytes());
//	
//		UDPdatagrampacket p_1 = new UDPdatagrampacket(1003, new pair<Integer, Integer>(1, 3), "Jonas".getBytes());
//		UDPdatagrampacket p_2 = new UDPdatagrampacket(1003, new pair<Integer, Integer>(2, 3), "Eyob".getBytes());
//		UDPdatagrampacket p_3 = new UDPdatagrampacket(1003, new pair<Integer, Integer>(3, 3), "DONE".getBytes());
//	
//		UDPdatagrampacket _p1_ = new UDPdatagrampacket(1004, new pair<Integer, Integer>(1, 3), "Jonas".getBytes());
//		UDPdatagrampacket _p2_ = new UDPdatagrampacket(1004, new pair<Integer, Integer>(2, 3), "Eyob".getBytes());
//		UDPdatagrampacket _p3_ = new UDPdatagrampacket(1004, new pair<Integer, Integer>(3, 3), "DONE".getBytes());
//		
//		UDPdataQueue q = new UDPdataQueue();
//		Thread t = new Thread(q);
//		t.start();
//		
//		UDPdatagrampacket[] testarray = new UDPdatagrampacket[]{p1,p2,p3,_p1,_p2,_p3,p1_,p2_,p3_,p_1,p_2,p_3,_p1_,_p2_,_p3_};
//		
//		for(UDPdatagrampacket packet : testarray){
//				q.push(packet);
//		}
//		
//		synchronized (q) {
//			q.notify();
//		}
//	}
//}
